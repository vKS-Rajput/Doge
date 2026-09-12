package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/db"
)

// openWorkspaceDB is a helper to open SQLite connection if workspace and db exist.
func (r *Runtime) openWorkspaceDB() (*db.DB, error) {
	r.mu.RLock()
	ws := r.workspace
	r.mu.RUnlock()

	if ws == nil || ws.RootPath == "" {
		return nil, fmt.Errorf("no active workspace")
	}

	dbPath := filepath.Join(ws.RootPath, ".doge", "workspace.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace database not found at %s", dbPath)
	}

	return db.Open(dbPath, db.Options{WALMode: true})
}

// GetNotebookSummary retrieves live investigation journal, notes, entity counts, and coverage metrics.
func (r *Runtime) GetNotebookSummary() (map[string]any, error) {
	r.mu.RLock()
	ws := r.workspace
	r.mu.RUnlock()

	res := map[string]any{
		"target":           "",
		"command_count":    0,
		"obs_count":        0,
		"artifact_count":   0,
		"entity_count":     0,
		"endpoint_count":   0,
		"parameter_count":  0,
		"technology_count": 0,
		"coverage_percent": 0.0,
		"notes":            []map[string]any{},
		"journal":          []map[string]any{},
	}

	if ws != nil {
		res["target"] = ws.Config.Target
	}

	database, err := r.openWorkspaceDB()
	if err != nil {
		// Workspace DB not created yet, return clean standby response
		return res, nil
	}
	defer database.Close()

	conn := database.Conn()

	var artCount, obsCount, entCount, epCount, paramCount, techCount int
	_ = conn.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&artCount)
	_ = conn.QueryRow("SELECT COUNT(*) FROM observations").Scan(&obsCount)
	_ = conn.QueryRow("SELECT COUNT(*) FROM entities").Scan(&entCount)
	_ = conn.QueryRow("SELECT COUNT(*) FROM entities WHERE type = 'endpoint'").Scan(&epCount)
	_ = conn.QueryRow("SELECT COUNT(*) FROM entities WHERE type = 'parameter'").Scan(&paramCount)
	_ = conn.QueryRow("SELECT COUNT(*) FROM entities WHERE type = 'technology'").Scan(&techCount)

	res["artifact_count"] = artCount
	res["obs_count"] = obsCount
	res["entity_count"] = entCount
	res["endpoint_count"] = epCount
	res["parameter_count"] = paramCount
	res["technology_count"] = techCount

	// Query timeline / journal events
	tRows, err := conn.Query("SELECT id, type, subject_type, action, occurred_at FROM timeline_events ORDER BY occurred_at DESC LIMIT 25")
	if err == nil {
		var journalEntries []map[string]any
		for tRows.Next() {
			var id, eType, subType, action, occurred string
			if err := tRows.Scan(&id, &eType, &subType, &action, &occurred); err == nil {
				journalEntries = append(journalEntries, map[string]any{
					"id":          id,
					"type":        eType,
					"subject":     subType,
					"action":      action,
					"occurred_at": occurred,
				})
			}
		}
		tRows.Close()
		res["journal"] = journalEntries
		res["command_count"] = len(journalEntries)
	}

	// Query researcher notes from observations
	nRows, err := conn.Query("SELECT id, raw_value, observed_at, data FROM observations WHERE type = 'researcher_note' ORDER BY observed_at DESC LIMIT 30")
	if err == nil {
		var notes []map[string]any
		for nRows.Next() {
			var id, raw, obsAt, dataStr string
			if err := nRows.Scan(&id, &raw, &obsAt, &dataStr); err == nil {
				var data map[string]any
				_ = json.Unmarshal([]byte(dataStr), &data)
				author := "researcher"
				category := "general"
				if a, ok := data["author"].(string); ok && a != "" {
					author = a
				}
				if c, ok := data["category"].(string); ok && c != "" {
					category = c
				}
				notes = append(notes, map[string]any{
					"id":          id,
					"text":        raw,
					"author":      author,
					"category":    category,
					"observed_at": obsAt,
				})
			}
		}
		nRows.Close()
		res["notes"] = notes
	}

	// Compute simple coverage metric
	var testedCount int
	_ = conn.QueryRow("SELECT COUNT(*) FROM tested_surfaces WHERE status = 'tested'").Scan(&testedCount)
	if epCount > 0 {
		cov := float64(testedCount) / float64(epCount) * 100.0
		if cov > 100.0 {
			cov = 100.0
		}
		res["coverage_percent"] = cov
	} else if testedCount > 0 {
		res["coverage_percent"] = 100.0
	}

	return res, nil
}

// AddResearcherNote inserts an operator or automated note into SQLite observations.
func (r *Runtime) AddResearcherNote(noteText, category, target string) (map[string]any, error) {
	database, err := r.openWorkspaceDB()
	if err != nil {
		return nil, err
	}
	defer database.Close()

	if category == "" {
		category = "operator_note"
	}

	data := map[string]any{
		"note":     noteText,
		"author":   "operator",
		"category": category,
	}
	if target != "" {
		data["target"] = target
	}

	dataBytes, _ := json.Marshal(data)
	hash := sha256.Sum256(dataBytes)
	checksum := hex.EncodeToString(hash[:])

	obsID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	projectID := uuid.Nil.String()
	// Find active project id if exists
	_ = database.Conn().QueryRow("SELECT id FROM projects LIMIT 1").Scan(&projectID)

	_, err = database.Conn().Exec(`
		INSERT OR IGNORE INTO observations
			(id, type, artifact_id, source_tool, project_id, data, raw_value,
			 checksum, observed_at, ingested_at, parser_version)
		VALUES (?, 'researcher_note', ?, 'operator', ?, ?, ?, ?, ?, ?, '1.0.0')
	`, obsID, uuid.Nil.String(), projectID, string(dataBytes), noteText, checksum, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to insert note: %w", err)
	}

	// Also record a timeline event
	_, _ = database.Conn().Exec(`
		INSERT INTO timeline_events (id, type, subject_type, subject_id, action, project_id, occurred_at)
		VALUES (?, 'note_added', 'observation', ?, 'Operator added research note', ?, ?)
	`, uuid.New().String(), obsID, projectID, now)

	// Broadcast note added event
	r.Broadcaster().Broadcast(EventObservationIngested, "operator", fmt.Sprintf("Note saved: %s", noteText), map[string]any{
		"id":          obsID,
		"text":        noteText,
		"observed_at": now,
	})

	return map[string]any{
		"id":          obsID,
		"text":        noteText,
		"observed_at": now,
	}, nil
}

// GetTargetSummary returns discovered hosts, endpoints, parameters, and technologies.
func (r *Runtime) GetTargetSummary() (map[string]any, error) {
	res := map[string]any{
		"hosts":        []map[string]any{},
		"endpoints":    []map[string]any{},
		"parameters":   []map[string]any{},
		"technologies": []map[string]any{},
		"ports":        []map[string]any{},
	}

	database, err := r.openWorkspaceDB()
	if err != nil {
		// If DB not ready, inspect in-memory world model
		r.mu.RLock()
		defer r.mu.RUnlock()
		if r.worldModel != nil {
			nodes, _ := r.worldModel.AttackGraphView()
			var eps []map[string]any
			for _, n := range nodes {
				eps = append(eps, map[string]any{
					"name":        n.Label,
					"type":        string(n.Role),
					"confidence":  n.Confidence,
					"novelty":     n.AnomalyScore,
					"last_tested": "Just now",
				})
			}
			res["endpoints"] = eps
		}
		return res, nil
	}
	defer database.Close()

	conn := database.Conn()

	// Query entities by type
	rows, err := conn.Query("SELECT id, type, value, attributes, observation_count, first_seen_at, last_seen_at FROM entities ORDER BY last_seen_at DESC LIMIT 200")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, eType, val, attrs, firstSeen, lastSeen string
			var obsCount int
			if err := rows.Scan(&id, &eType, &val, &attrs, &obsCount, &firstSeen, &lastSeen); err == nil {
				item := map[string]any{
					"id":                id,
					"type":              eType,
					"value":             val,
					"observation_count": obsCount,
					"first_seen_at":     firstSeen,
					"last_seen_at":      lastSeen,
				}
				switch eType {
				case "host", "subdomain", "domain":
					res["hosts"] = append(res["hosts"].([]map[string]any), item)
				case "endpoint", "url", "route":
					res["endpoints"] = append(res["endpoints"].([]map[string]any), item)
				case "parameter", "param":
					res["parameters"] = append(res["parameters"].([]map[string]any), item)
				case "technology", "tech", "framework":
					res["technologies"] = append(res["technologies"].([]map[string]any), item)
				case "port", "service":
					res["ports"] = append(res["ports"].([]map[string]any), item)
				default:
					res["endpoints"] = append(res["endpoints"].([]map[string]any), item)
				}
			}
		}
	}

	return res, nil
}

// GetResearchSummary returns active research questions, unknown space, hypotheses, and experiments.
func (r *Runtime) GetResearchSummary() (map[string]any, error) {
	r.mu.RLock()
	targetURL := ""
	if r.workspace != nil {
		targetURL = r.workspace.Config.Target
	}
	r.mu.RUnlock()

	res := map[string]any{
		"current_question": fmt.Sprintf("Evaluating authorization boundary and state invariants for %s", targetURL),
		"unknown_space":    []map[string]any{},
		"hypotheses":       []map[string]any{},
		"experiments":      []map[string]any{},
	}

	database, err := r.openWorkspaceDB()
	if err != nil {
		return res, nil
	}
	defer database.Close()

	conn := database.Conn()

	// Query hypotheses
	hRows, err := conn.Query("SELECT id, title, description, type, status, confidence FROM hypotheses ORDER BY created_at DESC LIMIT 20")
	if err == nil {
		var hypList []map[string]any
		for hRows.Next() {
			var id, title, desc, hType, status string
			var conf float64
			if err := hRows.Scan(&id, &title, &desc, &hType, &status, &conf); err == nil {
				hypList = append(hypList, map[string]any{
					"id":          id,
					"title":       title,
					"description": desc,
					"type":        hType,
					"status":      status,
					"confidence":  conf,
				})
			}
		}
		hRows.Close()
		res["hypotheses"] = hypList
	}

	// Query tested surfaces / unknown space
	sRows, err := conn.Query("SELECT id, category, status, notes FROM tested_surfaces ORDER BY updated_at DESC LIMIT 20")
	if err == nil {
		var unkList []map[string]any
		for sRows.Next() {
			var id, cat, status, notes string
			if err := sRows.Scan(&id, &cat, &status, &notes); err == nil {
				unkList = append(unkList, map[string]any{
					"id":       id,
					"category": cat,
					"status":   status,
					"notes":    notes,
				})
			}
		}
		sRows.Close()
		res["unknown_space"] = unkList
	}

	// Query tasks / experiments
	tRows, err := conn.Query("SELECT id, title, type, priority, risk, confidence, status FROM tasks ORDER BY created_at DESC LIMIT 20")
	if err == nil {
		var expList []map[string]any
		for tRows.Next() {
			var id, title, tType, prio, status string
			var risk, conf float64
			if err := tRows.Scan(&id, &title, &tType, &prio, &risk, &conf, &status); err == nil {
				expList = append(expList, map[string]any{
					"id":         id,
					"title":      title,
					"type":       tType,
					"priority":   prio,
					"risk":       risk,
					"confidence": conf,
					"status":     status,
				})
			}
		}
		tRows.Close()
		res["experiments"] = expList
	}

	return res, nil
}

// GetEvidenceSummary returns cryptographic proof bundles, observation artifacts, and timeline records.
func (r *Runtime) GetEvidenceSummary() (map[string]any, error) {
	r.mu.RLock()
	bundles := r.proofBundles
	r.mu.RUnlock()

	res := map[string]any{
		"proof_bundles": bundles,
		"evidence":      []map[string]any{},
		"artifacts":     []map[string]any{},
	}

	database, err := r.openWorkspaceDB()
	if err != nil {
		return res, nil
	}
	defer database.Close()

	conn := database.Conn()

	// Query evidence
	eRows, err := conn.Query("SELECT id, claim_type, type, description, source_location, strength, created_at FROM evidence ORDER BY created_at DESC LIMIT 30")
	if err == nil {
		var evList []map[string]any
		for eRows.Next() {
			var id, claimType, eType, desc, srcLoc, createdAt string
			var strength float64
			if err := eRows.Scan(&id, &claimType, &eType, &desc, &srcLoc, &strength, &createdAt); err == nil {
				evList = append(evList, map[string]any{
					"id":              id,
					"claim_type":      claimType,
					"type":            eType,
					"description":     desc,
					"source_location": srcLoc,
					"strength":        strength,
					"created_at":      createdAt,
				})
			}
		}
		eRows.Close()
		res["evidence"] = evList
	}

	// Query artifacts
	aRows, err := conn.Query("SELECT id, sha256, file_name, file_size, mime_type, imported_at FROM artifacts ORDER BY imported_at DESC LIMIT 30")
	if err == nil {
		var artList []map[string]any
		for aRows.Next() {
			var id, sha, fileName, mime, importedAt string
			var size int64
			if err := aRows.Scan(&id, &sha, &fileName, &size, &mime, &importedAt); err == nil {
				artList = append(artList, map[string]any{
					"id":          id,
					"sha256":      sha,
					"file_name":   fileName,
					"file_size":   size,
					"mime_type":   mime,
					"imported_at": importedAt,
				})
			}
		}
		aRows.Close()
		res["artifacts"] = artList
	}

	return res, nil
}
