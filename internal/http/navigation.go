package server

import (
	"sort"
	"strings"

	"secureshare/internal/auth"
	"secureshare/internal/config"
)

type NavigationItem struct {
	ID                  string
	Label               string
	URL                 string
	Icon                string
	Group               string
	Order               int
	RequiredPermissions []string
	MatchPatterns       []string
	Active              bool
}

type NavigationGroup struct {
	ID    string
	Label string
	Order int
	Items []NavigationItem
}

type NavigationModel struct {
	Groups  []NavigationGroup
	Account NavigationItem
}

var navigationItems = []NavigationItem{
	{ID: "dashboard", Label: "Dashboard", URL: "/admin", Icon: "home", Group: "workspace", Order: 10, RequiredPermissions: []string{"dashboard:read"}, MatchPatterns: []string{"=/admin"}},
	{ID: "create-secret", Label: "Create Secret", URL: "/admin/secrets/new", Icon: "plus", Group: "workspace", Order: 20, RequiredPermissions: []string{"secret:create"}, MatchPatterns: []string{"=/admin/secrets/new"}},
	{ID: "secret-links", Label: "Secret Links", URL: "/admin/secrets", Icon: "link", Group: "workspace", Order: 30, RequiredPermissions: []string{"secret:read-metadata"}, MatchPatterns: []string{"=/admin/secrets", "^/admin/secrets/"}},
	{ID: "api-clients", Label: "API Clients", URL: "/admin/api-clients", Icon: "key", Group: "access", Order: 10, RequiredPermissions: []string{"api-client:manage"}, MatchPatterns: []string{"=/admin/api-clients", "^/admin/api-clients/"}},
	{ID: "users", Label: "Users", URL: "/admin/users", Icon: "users", Group: "access", Order: 20, RequiredPermissions: []string{"user:manage"}, MatchPatterns: []string{"=/admin/users", "^/admin/users/"}},
	{ID: "email-settings", Label: "Email Settings", URL: "/admin/settings/email", Icon: "mail", Group: "settings", Order: 10, RequiredPermissions: []string{"email-settings:manage"}, MatchPatterns: []string{"=/admin/settings/email"}},
	{ID: "system-status", Label: "System Status", URL: "/admin/status", Icon: "status", Group: "settings", Order: 20, RequiredPermissions: []string{"system:read"}, MatchPatterns: []string{"=/admin/status", "=/admin/system"}},
	{ID: "api-docs", Label: "API Documentation", URL: "/docs", Icon: "book", Group: "resources", Order: 10, RequiredPermissions: []string{"api-docs:read"}, MatchPatterns: []string{"=/docs"}},
	{ID: "help", Label: "Help", URL: "/admin/help", Icon: "help", Group: "resources", Order: 20, RequiredPermissions: []string{"api-docs:read"}, MatchPatterns: []string{"=/admin/help"}},
	{ID: "account", Label: "Account", URL: "/admin/account", Icon: "account", Group: "account", Order: 10, RequiredPermissions: []string{"account:manage"}, MatchPatterns: []string{"=/admin/account"}},
}

var navigationGroups = []NavigationGroup{
	{ID: "workspace", Label: "Workspace", Order: 10},
	{ID: "access", Label: "Access", Order: 20},
	{ID: "settings", Label: "Settings", Order: 30},
	{ID: "resources", Label: "Resources", Order: 40},
}

func buildNavigation(cfg config.Config, session auth.Session, path string) NavigationModel {
	activeID := activeNavigationID(path)
	itemsByGroup := make(map[string][]NavigationItem)
	model := NavigationModel{}
	for _, definition := range navigationItems {
		if !navigationItemAvailable(cfg, definition) || !hasRequiredPermissions(session.Permissions, definition.RequiredPermissions) {
			continue
		}
		item := definition
		item.Active = item.ID == activeID
		if item.Group == "account" {
			model.Account = item
			continue
		}
		itemsByGroup[item.Group] = append(itemsByGroup[item.Group], item)
	}
	for _, definition := range navigationGroups {
		items := itemsByGroup[definition.ID]
		if len(items) == 0 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].Order < items[j].Order })
		group := definition
		group.Items = items
		model.Groups = append(model.Groups, group)
	}
	sort.SliceStable(model.Groups, func(i, j int) bool { return model.Groups[i].Order < model.Groups[j].Order })
	return model
}

func navigationItemAvailable(cfg config.Config, item NavigationItem) bool {
	if item.ID == "api-docs" {
		return cfg.SwaggerUIEnabled
	}
	return true
}

func hasRequiredPermissions(granted map[string]bool, required []string) bool {
	for _, permission := range required {
		if !granted[permission] {
			return false
		}
	}
	return true
}

func activeNavigationID(path string) string {
	for _, item := range navigationItems {
		for _, pattern := range item.MatchPatterns {
			if strings.HasPrefix(pattern, "=") && path == strings.TrimPrefix(pattern, "=") {
				return item.ID
			}
		}
	}
	for _, item := range navigationItems {
		for _, pattern := range item.MatchPatterns {
			if strings.HasPrefix(pattern, "^") && strings.HasPrefix(path, strings.TrimPrefix(pattern, "^")) {
				return item.ID
			}
		}
	}
	return ""
}

func navigationItemIDs(model NavigationModel) []string {
	ids := make([]string, 0, len(navigationItems))
	for _, group := range model.Groups {
		for _, item := range group.Items {
			ids = append(ids, item.ID)
		}
	}
	if model.Account.ID != "" {
		ids = append(ids, model.Account.ID)
	}
	return ids
}
