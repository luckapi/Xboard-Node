package model

func RouteSupportMatrix() map[string]KernelRouteSupport {
	return map[string]KernelRouteSupport{
		"xray": {
			Matchers: []string{
				"domain_keywords",
				"domains",
				"domain_suffixes",
				"ip_cidrs",
				"ports",
				"networks",
				"source_cidrs",
				"source_ports",
			},
			Actions: []string{"block", "direct", "route"},
		},
		"singbox": {
			Matchers: []string{
				"domain_keywords",
				"domains",
				"domain_suffixes",
				"ip_cidrs",
				"ports",
				"networks",
				"source_cidrs",
				"source_ports",
			},
			Actions: []string{"block", "direct", "route"},
		},
	}
}

type KernelRouteSupport struct {
	Matchers []string
	Actions  []string
}
