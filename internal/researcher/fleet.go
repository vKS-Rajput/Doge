package researcher

import "github.com/vKS-Rajput/doge/pkg/domain"

// Fleet manages the collection of all specialized researchers.
type Fleet struct {
	researchers map[domain.ResearcherType]Researcher
}

// NewResearcherFleet instantiates all 14 specialized researchers with the provided client.
func NewResearcherFleet(client HTTPClient) *Fleet {
	f := &Fleet{
		researchers: make(map[domain.ResearcherType]Researcher),
	}
	f.Register(NewReconResearcher(client))
	f.Register(NewAPIResearcher(client))
	f.Register(NewAuthenticationResearcher(client))
	f.Register(NewAuthorizationResearcher(client))
	f.Register(NewDifferentialResearcher(client))
	f.Register(NewMetamorphicResearcher(client))
	f.Register(NewRaceResearcher(client))
	f.Register(NewCacheResearcher(client))
	f.Register(NewInjectionResearcher(client))
	f.Register(NewChainResearcher(client, nil))
	f.Register(NewExploitResearcher(client))
	f.Register(NewSourceResearcher("."))
	f.Register(NewValidationResearcher(client))
	f.Register(NewImpactResearcher(client))
	return f
}

func (f *Fleet) Register(r Researcher) {
	if r != nil {
		f.researchers[r.Type()] = r
	}
}

func (f *Fleet) Get(rType domain.ResearcherType) Researcher {
	return f.researchers[rType]
}

func (f *Fleet) ListCapabilities() []domain.ResearcherType {
	var list []domain.ResearcherType
	for t := range f.researchers {
		list = append(list, t)
	}
	return list
}
