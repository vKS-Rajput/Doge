// Package insight provides deterministic, rule-based pattern detection.
//
// The Insight Engine subscribes to entity.created events and evaluates
// each new entity against a set of rules. When a rule matches, an
// Insight is created and persisted.
//
// No AI. No LLM. Pure deterministic rules.
//
// The flow is:
//
//	entity.created event
//	    ↓
//	Rule evaluation
//	    ↓
//	Insight persisted
//	    ↓
//	insight.detected event
//	    ↓
//	Task Engine (subscriber)
package insight

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Severity classifies the importance of an insight.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Insight is a detected pattern or notable finding.
type Insight struct {
	ID          uuid.UUID   `json:"id"`
	Type        string      `json:"type"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	EntityIDs   []uuid.UUID `json:"entity_ids"`
	RuleID      string      `json:"rule_id"`
	ProjectID   uuid.UUID   `json:"project_id"`
	DetectedAt  time.Time   `json:"detected_at"`
}

// Rule defines a single detection rule. Rules are pure functions:
// they receive entity context and return zero or more insights.
type Rule struct {
	ID          string   // Unique rule identifier (e.g., "admin_path").
	Name        string   // Human-readable name.
	Description string   // What this rule detects.
	Severity    Severity // Default severity for matches.
	EntityTypes []string // Which entity types this rule evaluates.
	Evaluate    func(entityType, entityValue string, attrs map[string]any) *Match
}

// Match is the output of a successful rule evaluation.
type Match struct {
	Title       string
	Description string
	Severity    Severity // Override default if set.
}

// Engine evaluates rules against entities and persists insights.
type Engine struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
	rules  []Rule
}

// NewEngine creates a new Insight Engine with built-in rules.
func NewEngine(db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Engine {
	e := &Engine{
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
	e.rules = builtinRules()
	return e
}

// Subscribe registers the insight engine as a handler for entity events.
func (e *Engine) Subscribe() {
	e.bus.Subscribe(events.TopicEntityCreated, e.onEntityCreated)
	e.logger.Info("insight engine subscribed", "rules", len(e.rules))
}

// Query returns insights matching the filter.
func (e *Engine) Query(ctx context.Context, projectID uuid.UUID, limit int) ([]Insight, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := e.db.QueryContext(ctx,
		`SELECT id, type, title, description, severity, entity_ids, rule_id, project_id, detected_at
		 FROM insights WHERE project_id = ?
		 ORDER BY detected_at DESC LIMIT ?`,
		projectID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var insights []Insight
	for rows.Next() {
		i, err := scanInsight(rows)
		if err != nil {
			continue
		}
		insights = append(insights, i)
	}
	return insights, rows.Err()
}

func (e *Engine) onEntityCreated(ctx context.Context, event events.Event) error {
	ec := event.(events.EntityCreated)

	for _, rule := range e.rules {
		// Check if rule applies to this entity type.
		if !ruleApplies(rule, ec.Type) {
			continue
		}

		// Evaluate the rule.
		// For now, we pass empty attrs since the event doesn't carry them.
		// The rule works on type + value which is sufficient for pattern matching.
		match := rule.Evaluate(ec.Type, ec.Value, nil)
		if match == nil {
			continue
		}

		severity := rule.Severity
		if match.Severity != "" {
			severity = match.Severity
		}

		insight := Insight{
			ID:          uuid.New(),
			Type:        rule.ID,
			Title:       match.Title,
			Description: match.Description,
			Severity:    severity,
			EntityIDs:   []uuid.UUID{ec.EntityID},
			RuleID:      rule.ID,
			ProjectID:   ec.ProjectID,
			DetectedAt:  time.Now().UTC(),
		}

		if err := e.persist(ctx, insight); err != nil {
			e.logger.Warn("failed to persist insight", "rule", rule.ID, "error", err)
			continue
		}

		e.logger.Info("insight detected",
			"rule", rule.ID,
			"severity", string(severity),
			"title", match.Title,
			"entity", ec.Value,
		)

		// Emit event.
		ruleID := rule.ID
		e.bus.Publish(ctx, events.InsightDetected{
			BaseEvent: events.NewBaseEvent(),
			InsightID: insight.ID,
			Type:      rule.ID,
			Severity:  string(severity),
			EntityIDs: []uuid.UUID{ec.EntityID},
			RuleID:    &ruleID,
		})
	}

	return nil
}

func (e *Engine) persist(ctx context.Context, insight Insight) error {
	entityIDsJSON, _ := json.Marshal(uuidStrings(insight.EntityIDs))

	_, err := e.db.ExecContext(ctx,
		`INSERT INTO insights (id, type, title, description, severity, entity_ids, rule_id, project_id, detected_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		insight.ID.String(), insight.Type, insight.Title, insight.Description,
		string(insight.Severity), string(entityIDsJSON), insight.RuleID,
		insight.ProjectID.String(), insight.DetectedAt.Format(time.RFC3339))
	return err
}

func ruleApplies(rule Rule, entityType string) bool {
	if len(rule.EntityTypes) == 0 {
		return true // Rule applies to all types.
	}
	for _, t := range rule.EntityTypes {
		if t == entityType {
			return true
		}
	}
	return false
}

func uuidStrings(ids []uuid.UUID) []string {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	return strs
}

func scanInsight(rows *sql.Rows) (Insight, error) {
	var i Insight
	var id, insightType, title, desc, severity, entityIDsJSON, ruleID, projectID, detectedAt string

	err := rows.Scan(&id, &insightType, &title, &desc, &severity,
		&entityIDsJSON, &ruleID, &projectID, &detectedAt)
	if err != nil {
		return i, err
	}

	i.ID = uuid.MustParse(id)
	i.Type = insightType
	i.Title = title
	i.Description = desc
	i.Severity = Severity(severity)
	i.RuleID = ruleID
	i.ProjectID = uuid.MustParse(projectID)
	i.DetectedAt, _ = time.Parse(time.RFC3339, detectedAt)

	var entityIDStrs []string
	_ = json.Unmarshal([]byte(entityIDsJSON), &entityIDStrs)
	for _, s := range entityIDStrs {
		if uid, err := uuid.Parse(s); err == nil {
			i.EntityIDs = append(i.EntityIDs, uid)
		}
	}

	return i, nil
}

// --- Built-in Rules ---

func builtinRules() []Rule {
	return []Rule{
		ruleAdminPath(),
		ruleAPIEndpoint(),
		ruleSensitivePath(),
		ruleInsecureHTTP(),
		ruleInterestingTechnology(),
		ruleDefaultCredentialPath(),
		ruleDebugEndpoint(),
		ruleFileUpload(),
	}
}

func ruleAdminPath() Rule {
	adminPatterns := []string{
		"/admin", "/administrator", "/wp-admin", "/panel",
		"/dashboard", "/manage", "/console", "/control",
		"/cpanel", "/backend", "/backoffice", "/phpmyadmin",
	}
	return Rule{
		ID:          "admin_path",
		Name:        "Admin Path Detected",
		Description: "URL contains an administrative path, which may expose management interfaces.",
		Severity:    SeverityHigh,
		EntityTypes: []string{"url", "endpoint"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for _, pattern := range adminPatterns {
				if strings.Contains(lower, pattern) {
					return &Match{
						Title:       fmt.Sprintf("Admin path detected: %s", truncate(value, 60)),
						Description: fmt.Sprintf("URL contains '%s'. Administrative interfaces may expose sensitive controls.", pattern),
					}
				}
			}
			return nil
		},
	}
}

func ruleAPIEndpoint() Rule {
	apiPatterns := []string{"/api/", "/api/v", "/graphql", "/rest/", "/swagger", "/openapi"}
	return Rule{
		ID:          "api_endpoint",
		Name:        "API Endpoint Detected",
		Description: "URL exposes an API endpoint that may have different authentication or authorization controls.",
		Severity:    SeverityMedium,
		EntityTypes: []string{"url", "endpoint"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for _, pattern := range apiPatterns {
				if strings.Contains(lower, pattern) {
					return &Match{
						Title:       fmt.Sprintf("API endpoint detected: %s", truncate(value, 60)),
						Description: fmt.Sprintf("URL contains '%s'. API endpoints often have weaker access controls.", pattern),
					}
				}
			}
			return nil
		},
	}
}

func ruleSensitivePath() Rule {
	sensitivePatterns := []string{
		"/.env", "/.git", "/config", "/backup",
		"/.htaccess", "/web.config", "/.svn",
		"/debug", "/.DS_Store", "/server-status",
		"/elmah.axd", "/trace.axd",
	}
	return Rule{
		ID:          "sensitive_path",
		Name:        "Sensitive Path Detected",
		Description: "URL references a path that may expose configuration or version control data.",
		Severity:    SeverityHigh,
		EntityTypes: []string{"url", "endpoint"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(lower, pattern) {
					return &Match{
						Title:       fmt.Sprintf("Sensitive path detected: %s", truncate(value, 60)),
						Description: fmt.Sprintf("URL contains '%s'. This may expose sensitive configuration data.", pattern),
					}
				}
			}
			return nil
		},
	}
}

func ruleInsecureHTTP() Rule {
	return Rule{
		ID:          "insecure_http",
		Name:        "Insecure HTTP URL",
		Description: "URL uses HTTP instead of HTTPS, which transmits data in plaintext.",
		Severity:    SeverityMedium,
		EntityTypes: []string{"url"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			if strings.HasPrefix(strings.ToLower(value), "http://") {
				return &Match{
					Title:       fmt.Sprintf("Insecure HTTP: %s", truncate(value, 60)),
					Description: "This URL uses HTTP instead of HTTPS. Data may be transmitted in plaintext.",
				}
			}
			return nil
		},
	}
}

func ruleInterestingTechnology() Rule {
	interesting := map[string]string{
		"wordpress": "CMS — check for known vulnerabilities and exposed wp-admin",
		"drupal":    "CMS — check for known CVEs and exposed admin paths",
		"joomla":    "CMS — check for known vulnerabilities",
		"phpmyadmin": "Database management — check for default credentials",
		"jenkins":   "CI/CD — check for unauthenticated access",
		"grafana":   "Monitoring — check for default credentials",
		"tomcat":    "Application server — check for manager interface",
		"weblogic":  "Application server — check for known CVEs",
		"elasticsearch": "Search engine — check for unauthenticated access",
		"kibana":    "Visualization — check for unauthenticated access",
		"rabbitmq":  "Message broker — check for management interface",
		"redis":     "Cache — check for unauthenticated access",
	}
	return Rule{
		ID:          "interesting_technology",
		Name:        "Notable Technology Detected",
		Description: "A technology known to have common misconfigurations or vulnerabilities was detected.",
		Severity:    SeverityMedium,
		EntityTypes: []string{"technology"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for tech, reason := range interesting {
				if strings.Contains(lower, tech) {
					return &Match{
						Title:       fmt.Sprintf("Notable technology: %s", value),
						Description: reason,
					}
				}
			}
			return nil
		},
	}
}

func ruleDefaultCredentialPath() Rule {
	paths := []string{
		"/login", "/signin", "/auth", "/sso",
		"/oauth", "/saml", "/cas",
	}
	return Rule{
		ID:          "auth_endpoint",
		Name:        "Authentication Endpoint Detected",
		Description: "URL contains an authentication path. Test for default/weak credentials and bypass techniques.",
		Severity:    SeverityMedium,
		EntityTypes: []string{"url", "endpoint"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for _, pattern := range paths {
				if strings.Contains(lower, pattern) {
					return &Match{
						Title:       fmt.Sprintf("Auth endpoint: %s", truncate(value, 60)),
						Description: fmt.Sprintf("URL contains '%s'. Test for default credentials, bypass, and brute-force.", pattern),
					}
				}
			}
			return nil
		},
	}
}

func ruleDebugEndpoint() Rule {
	patterns := []string{
		"/debug", "/trace", "/profiler", "/metrics",
		"/health", "/actuator", "/_debug", "/phpinfo",
	}
	return Rule{
		ID:          "debug_endpoint",
		Name:        "Debug/Monitoring Endpoint Detected",
		Description: "URL references a debug or monitoring endpoint that may expose internal state.",
		Severity:    SeverityHigh,
		EntityTypes: []string{"url", "endpoint"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for _, pattern := range patterns {
				if strings.Contains(lower, pattern) {
					return &Match{
						Title:       fmt.Sprintf("Debug endpoint: %s", truncate(value, 60)),
						Description: fmt.Sprintf("URL contains '%s'. Debug endpoints may expose internal state.", pattern),
					}
				}
			}
			return nil
		},
	}
}

func ruleFileUpload() Rule {
	patterns := []string{"/upload", "/file", "/attachment", "/import"}
	return Rule{
		ID:          "file_upload",
		Name:        "File Upload Endpoint Detected",
		Description: "URL contains a file upload path. Test for unrestricted file upload vulnerabilities.",
		Severity:    SeverityMedium,
		EntityTypes: []string{"url", "endpoint"},
		Evaluate: func(entityType, value string, _ map[string]any) *Match {
			lower := strings.ToLower(value)
			for _, pattern := range patterns {
				if strings.Contains(lower, pattern) {
					return &Match{
						Title:       fmt.Sprintf("Upload endpoint: %s", truncate(value, 60)),
						Description: fmt.Sprintf("URL contains '%s'. Test for unrestricted file upload.", pattern),
					}
				}
			}
			return nil
		},
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
