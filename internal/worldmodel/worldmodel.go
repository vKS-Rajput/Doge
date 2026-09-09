package worldmodel

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

var (
	objIDPathRegex = regexp.MustCompile(`/(?:users|accounts|profiles|orders|items|files|documents|invoices|messages|conversations|orgs|organizations|teams|projects|reports)/([0-9a-fA-F-]{4,36}|\d+)`)
	urlParamRegex  = regexp.MustCompile(`(?i)^(?:url|uri|dest|dest_url|destination|redirect|redirect_to|next|callback|webhook|webhook_url|feed|proxy|source|target_url|load_url|fetch|image_url|avatar_url|endpoint|redirect_url|return_url)$`)
)

// WorldModel is the central, unified, thread-safe relational world state of an investigated application.
type WorldModel struct {
	mu                     sync.RWMutex
	target                 string
	principals             map[uuid.UUID]*Principal
	tenants                map[uuid.UUID]*Tenant
	accounts               map[uuid.UUID]*Account
	objects                map[uuid.UUID]*ObjectResource
	endpoints              map[uuid.UUID]*EndpointModel
	endpointByURL          map[string]*EndpointModel
	parameters             map[uuid.UUID]*ParameterModel
	states                 map[string]*StateNode
	transitions            []*StateTransition
	relationships          []*WorldRelationship
	relationshipsBySource  map[uuid.UUID][]*WorldRelationship
	relationshipsByTarget  map[uuid.UUID][]*WorldRelationship
	gaps                   map[uuid.UUID]*ResearchGap
	detector               *ResearchGapDetector
	lastUpdatedAt          time.Time
}

// NewWorldModel instantiates a new empty WorldModel for an investigation target.
func NewWorldModel(target string) *WorldModel {
	wm := &WorldModel{
		target:                target,
		principals:            make(map[uuid.UUID]*Principal),
		tenants:               make(map[uuid.UUID]*Tenant),
		accounts:              make(map[uuid.UUID]*Account),
		objects:               make(map[uuid.UUID]*ObjectResource),
		endpoints:             make(map[uuid.UUID]*EndpointModel),
		endpointByURL:         make(map[string]*EndpointModel),
		parameters:            make(map[uuid.UUID]*ParameterModel),
		states:                make(map[string]*StateNode),
		transitions:           make([]*StateTransition, 0),
		relationships:         make([]*WorldRelationship, 0),
		relationshipsBySource: make(map[uuid.UUID][]*WorldRelationship),
		relationshipsByTarget: make(map[uuid.UUID][]*WorldRelationship),
		gaps:                  make(map[uuid.UUID]*ResearchGap),
		lastUpdatedAt:         time.Now().UTC(),
	}
	wm.detector = NewResearchGapDetector(wm)
	return wm
}

// Target returns the root target of this world model.
func (wm *WorldModel) Target() string {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.target
}

// RegisterPrincipal adds a security principal into the world model.
func (wm *WorldModel) RegisterPrincipal(p *Principal) error {
	if p == nil {
		return fmt.Errorf("cannot register nil principal")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	wm.principals[p.ID] = p
	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// GetPrincipal returns a principal by ID.
func (wm *WorldModel) GetPrincipal(id uuid.UUID) (*Principal, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	p, ok := wm.principals[id]
	return p, ok
}

// ListPrincipals returns all registered principals.
func (wm *WorldModel) ListPrincipals() []*Principal {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	res := make([]*Principal, 0, len(wm.principals))
	for _, p := range wm.principals {
		res = append(res, p)
	}
	return res
}

// RegisterTenant adds a tenant into the world model.
func (wm *WorldModel) RegisterTenant(t *Tenant) error {
	if t == nil {
		return fmt.Errorf("cannot register nil tenant")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	wm.tenants[t.ID] = t
	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// GetTenant returns a tenant by ID.
func (wm *WorldModel) GetTenant(id uuid.UUID) (*Tenant, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	t, ok := wm.tenants[id]
	return t, ok
}

// ListTenants returns all registered tenants.
func (wm *WorldModel) ListTenants() []*Tenant {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	res := make([]*Tenant, 0, len(wm.tenants))
	for _, t := range wm.tenants {
		res = append(res, t)
	}
	return res
}

// RegisterAccount adds an account into the world model.
func (wm *WorldModel) RegisterAccount(a *Account) error {
	if a == nil {
		return fmt.Errorf("cannot register nil account")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	wm.accounts[a.ID] = a
	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// RegisterObject adds an object resource into the world model and establishes ownership relations.
func (wm *WorldModel) RegisterObject(obj *ObjectResource) error {
	if obj == nil {
		return fmt.Errorf("cannot register nil object")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if obj.ID == uuid.Nil {
		obj.ID = uuid.New()
	}
	if obj.CreatedAt.IsZero() {
		obj.CreatedAt = time.Now().UTC()
	}
	wm.objects[obj.ID] = obj

	// Establish relations
	if obj.OwnerPrincipalID != nil {
		wm.addRelationshipInternal(*obj.OwnerPrincipalID, obj.ID, domain.RelOwnsObject, nil)
	}
	if obj.TenantID != nil {
		wm.addRelationshipInternal(*obj.TenantID, obj.ID, domain.RelPartOf, nil)
	}

	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// GetObject returns an object resource by ID.
func (wm *WorldModel) GetObject(id uuid.UUID) (*ObjectResource, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	obj, ok := wm.objects[id]
	return obj, ok
}

// ListObjects returns all registered objects.
func (wm *WorldModel) ListObjects() []*ObjectResource {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	res := make([]*ObjectResource, 0, len(wm.objects))
	for _, obj := range wm.objects {
		res = append(res, obj)
	}
	return res
}

// RegisterEndpoint adds or enriches an endpoint in the world model.
func (wm *WorldModel) RegisterEndpoint(ep *EndpointModel) error {
	if ep == nil {
		return fmt.Errorf("cannot register nil endpoint")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	normURL := normalizeEndpointKey(ep.URL, ep.Host, ep.Path, ep.Method)
	if existing, ok := wm.endpointByURL[normURL]; ok {
		// Enrich existing
		if ep.RequiresAuth {
			existing.RequiresAuth = true
		}
		if len(ep.RequiredRoles) > 0 {
			existing.RequiredRoles = append(existing.RequiredRoles, ep.RequiredRoles...)
		}
		if len(ep.Parameters) > 0 {
			existing.Parameters = append(existing.Parameters, ep.Parameters...)
		}
		return nil
	}

	if ep.ID == uuid.Nil {
		ep.ID = uuid.New()
	}
	if ep.FirstSeenAt.IsZero() {
		ep.FirstSeenAt = time.Now().UTC()
	}
	wm.endpoints[ep.ID] = ep
	wm.endpointByURL[normURL] = ep

	// Register parameter relationships
	for _, param := range ep.Parameters {
		if param.ID == uuid.Nil {
			param.ID = uuid.New()
		}
		param.EndpointID = ep.ID
		wm.parameters[param.ID] = param
		wm.addRelationshipInternal(ep.ID, param.ID, domain.RelAcceptsParam, map[string]any{
			"param_name": param.Name,
			"location":   param.Location,
		})
	}

	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// GetEndpoint returns an endpoint by ID.
func (wm *WorldModel) GetEndpoint(id uuid.UUID) (*EndpointModel, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	ep, ok := wm.endpoints[id]
	return ep, ok
}

// GetEndpointByURL retrieves an endpoint model by matching its normalized URL key.
func (wm *WorldModel) GetEndpointByURL(rawURL string) (*EndpointModel, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	norm := normalizeEndpointKey(rawURL, "", "", "")
	ep, ok := wm.endpointByURL[norm]
	return ep, ok
}

// ListEndpoints returns all registered endpoints.
func (wm *WorldModel) ListEndpoints() []*EndpointModel {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	res := make([]*EndpointModel, 0, len(wm.endpoints))
	for _, ep := range wm.endpoints {
		res = append(res, ep)
	}
	return res
}

// RegisterStateNode registers a distinct application workflow state.
func (wm *WorldModel) RegisterStateNode(node *StateNode) error {
	if node == nil {
		return fmt.Errorf("cannot register nil state node")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if node.ID == uuid.Nil {
		node.ID = uuid.New()
	}
	wm.states[node.Name] = node
	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// RegisterStateTransition registers a valid or candidate workflow state transition.
func (wm *WorldModel) RegisterStateTransition(st *StateTransition) error {
	if st == nil {
		return fmt.Errorf("cannot register nil state transition")
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if st.ID == uuid.Nil {
		st.ID = uuid.New()
	}
	wm.transitions = append(wm.transitions, st)
	wm.lastUpdatedAt = time.Now().UTC()
	return nil
}

// ListStateTransitions returns all recorded workflow state transitions.
func (wm *WorldModel) ListStateTransitions() []*StateTransition {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	res := make([]*StateTransition, len(wm.transitions))
	copy(res, wm.transitions)
	return res
}

// AddRelationship creates a directed relational edge in the world graph.
func (wm *WorldModel) AddRelationship(sourceID, targetID uuid.UUID, relType domain.RelationshipType, attrs map[string]any) *WorldRelationship {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return wm.addRelationshipInternal(sourceID, targetID, relType, attrs)
}

func (wm *WorldModel) addRelationshipInternal(sourceID, targetID uuid.UUID, relType domain.RelationshipType, attrs map[string]any) *WorldRelationship {
	rel := &WorldRelationship{
		ID:         uuid.New(),
		SourceID:   sourceID,
		TargetID:   targetID,
		Type:       relType,
		Attributes: attrs,
		CreatedAt:  time.Now().UTC(),
	}
	wm.relationships = append(wm.relationships, rel)
	wm.relationshipsBySource[sourceID] = append(wm.relationshipsBySource[sourceID], rel)
	wm.relationshipsByTarget[targetID] = append(wm.relationshipsByTarget[targetID], rel)
	return rel
}

// GetOutboundRelationships returns all relationships originating from sourceID.
func (wm *WorldModel) GetOutboundRelationships(sourceID uuid.UUID) []*WorldRelationship {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	rels := wm.relationshipsBySource[sourceID]
	res := make([]*WorldRelationship, len(rels))
	copy(res, rels)
	return res
}

// GetInboundRelationships returns all relationships targeting targetID.
func (wm *WorldModel) GetInboundRelationships(targetID uuid.UUID) []*WorldRelationship {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	rels := wm.relationshipsByTarget[targetID]
	res := make([]*WorldRelationship, len(rels))
	copy(res, rels)
	return res
}

// AddGap registers a research gap in the world model.
func (wm *WorldModel) AddGap(gap *ResearchGap) {
	if gap == nil {
		return
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if gap.ID == uuid.Nil {
		gap.ID = uuid.New()
	}
	if gap.DiscoveredAt.IsZero() {
		gap.DiscoveredAt = time.Now().UTC()
	}
	wm.gaps[gap.ID] = gap
	wm.lastUpdatedAt = time.Now().UTC()
}

// GetGap returns a research gap by ID.
func (wm *WorldModel) GetGap(id uuid.UUID) (*ResearchGap, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	gap, ok := wm.gaps[id]
	return gap, ok
}

// ListGaps returns all research gaps.
func (wm *WorldModel) ListGaps() []*ResearchGap {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	res := make([]*ResearchGap, 0, len(wm.gaps))
	for _, g := range wm.gaps {
		res = append(res, g)
	}
	return res
}

// ListOpenGaps returns all open or investigating research gaps.
func (wm *WorldModel) ListOpenGaps() []*ResearchGap {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	var res []*ResearchGap
	for _, g := range wm.gaps {
		if g.Status == GapStatusOpen || g.Status == GapStatusInvestigating {
			res = append(res, g)
		}
	}
	return res
}

// ResolveGap marks a research gap as resolved with supporting evidence proof.
func (wm *WorldModel) ResolveGap(id uuid.UUID, proof string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	if g, ok := wm.gaps[id]; ok {
		g.Status = GapStatusResolved
		now := time.Now().UTC()
		g.ResolvedAt = &now
		g.ResolutionProof = proof
		g.Uncertainty = 0.0
		wm.lastUpdatedAt = now
	}
}

// IngestEntitiesAndObservations synchronizes knowledge graph telemetry into structured world model nodes.
func (wm *WorldModel) IngestEntitiesAndObservations(entities []domain.Entity, observations []domain.Observation) {
	for _, ent := range entities {
		switch ent.Type {
		case domain.EntityEndpoint, domain.EntityURL:
			val := ent.Value
			host := ""
			path := val
			if u, err := url.Parse(val); err == nil && u.Host != "" {
				host = u.Host
				path = u.Path
			}
			ep := &EndpointModel{
				ID:          ent.ID,
				Host:        host,
				Path:        path,
				Method:      "GET",
				URL:         val,
				FirstSeenAt: time.Now().UTC(),
			}

			// Extract object identifiers from URL path
			if matches := objIDPathRegex.FindStringSubmatch(val); len(matches) == 2 {
				objID := matches[1]
				obj := &ObjectResource{
					ID:          uuid.New(),
					Type:        "resource_object",
					Identifier:  objID,
					EndpointID:  &ep.ID,
					EndpointURL: val,
					CreatedAt:   time.Now().UTC(),
				}
				_ = wm.RegisterObject(obj)
			}
			_ = wm.RegisterEndpoint(ep)

		case domain.EntityParameter:
			paramName := ent.Value
			isURL := urlParamRegex.MatchString(paramName)
			pm := &ParameterModel{
				ID:             ent.ID,
				Name:           paramName,
				Location:       "query",
				IsURLParameter: isURL,
			}
			wm.mu.Lock()
			wm.parameters[pm.ID] = pm
			wm.mu.Unlock()
		}
	}

	// Auto-trigger Gap Detection after ingestion
	gaps := wm.detector.DetectGaps()
	for _, g := range gaps {
		wm.AddGap(g)
	}
}

// DetectGaps runs the ResearchGapDetector on current world model state.
func (wm *WorldModel) DetectGaps() []*ResearchGap {
	return wm.detector.DetectGaps()
}

func normalizeEndpointKey(rawURL, host, path, method string) string {
	if rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
			return strings.ToLower(fmt.Sprintf("%s:%s%s", method, u.Host, u.Path))
		}
		return strings.ToLower(rawURL)
	}
	return strings.ToLower(fmt.Sprintf("%s:%s%s", method, host, path))
}
