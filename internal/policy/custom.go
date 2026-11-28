package policy

import (
	"regexp"
	"sort"
	"strconv"

	"github.com/HUA503/mcprism/internal/rules"
)

type compiledCustomRule struct {
	rule CustomRule
	re   *regexp.Regexp
}

type customCandidate struct {
	value    string
	location string
}

func compileCustomRules(customRules []CustomRule) []compiledCustomRule {
	compiled := make([]compiledCustomRule, 0, len(customRules))
	for _, rule := range customRules {
		re, err := regexp.Compile(rule.Pattern)
		if err == nil {
			compiled = append(compiled, compiledCustomRule{rule: rule, re: re})
		}
	}
	return compiled
}

func applyCustomRules(result *rules.Result, input *rules.Input, customRules []compiledCustomRule) {
	if result == nil || len(customRules) == 0 {
		return
	}
	// Match only the original scan findings. A custom rule must not trigger
	// another custom rule through the finding fields it just created.
	originalFindings := append([]rules.Finding(nil), result.Findings...)
	for _, custom := range customRules {
		for _, candidate := range customCandidates(custom.rule.Field, result, input, originalFindings) {
			if !custom.re.MatchString(candidate.value) {
				continue
			}
			location := candidate.location
			if location == "" {
				location = "policy:" + custom.rule.Field
			}
			result.Findings = append(result.Findings, rules.Finding{
				RuleID: custom.rule.ID, Title: custom.rule.Title,
				Severity: normalizeSeverity(custom.rule.Severity), Server: result.ServerName,
				Location: location, Evidence: "custom policy pattern matched field " + custom.rule.Field,
				Description: custom.rule.Description, Advice: custom.rule.Advice,
			})
		}
	}
}

func customCandidates(field string, result *rules.Result, input *rules.Input, findings []rules.Finding) []customCandidate {
	add := func(out []customCandidate, value, location string) []customCandidate {
		if value != "" {
			out = append(out, customCandidate{value: value, location: location})
		}
		return out
	}
	var out []customCandidate
	var serverName, command, url, transport, source, client, cwd string
	if input != nil && input.Server != nil {
		serverName = input.Server.Name
		command = input.Server.Command
		url = input.Server.URL
		transport = string(input.Server.Transport)
		client = input.Server.Client
		cwd = input.Server.Cwd
	}
	if result.Server != nil {
		if serverName == "" {
			serverName = result.Server.Name
		}
		if command == "" {
			command = result.Server.Command
		}
		if url == "" {
			url = result.Server.URL
		}
		if transport == "" {
			transport = string(result.Server.Transport)
		}
		if client == "" {
			client = result.Server.Client
		}
		if cwd == "" {
			cwd = result.Server.Cwd
		}
	}
	if result.Source != "" {
		source = result.Source
	} else if input != nil && input.Server != nil {
		source = input.Server.Source
	}

	switch field {
	case "server.name":
		out = add(out, serverName, "server:name")
	case "server.command":
		out = add(out, command, "server:command")
	case "server.args":
		if input != nil && input.Server != nil {
			for i, arg := range input.Server.Args {
				out = add(out, arg, "server:arg["+strconv.Itoa(i)+"]")
			}
		} else if result.Server != nil {
			for i, arg := range result.Server.Args {
				out = add(out, arg, "server:arg["+strconv.Itoa(i)+"]")
			}
		}
	case "server.url":
		out = add(out, url, "server:url")
	case "server.target":
		out = add(out, result.Target, "server:target")
	case "server.transport":
		out = add(out, transport, "server:transport")
	case "server.cwd":
		out = add(out, cwd, "server:cwd")
	case "server.source":
		out = add(out, source, "server:source")
	case "server.client":
		out = add(out, client, "server:client")
	case "server.env_key":
		if input != nil && input.Server != nil {
			keys := make([]string, 0, len(input.Server.Env))
			for key := range input.Server.Env {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				out = add(out, key, "server:env."+key)
			}
		} else if result.Server != nil {
			keys := make([]string, 0, len(result.Server.Env))
			for key := range result.Server.Env {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				out = add(out, key, "server:env."+key)
			}
		}
	case "server.header_key":
		if input != nil && input.Server != nil {
			keys := make([]string, 0, len(input.Server.Headers))
			for key := range input.Server.Headers {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				out = add(out, key, "server:header."+key)
			}
		} else if result.Server != nil {
			keys := make([]string, 0, len(result.Server.Headers))
			for key := range result.Server.Headers {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				out = add(out, key, "server:header."+key)
			}
		}
	case "tool.name", "tool.title", "tool.description", "tool.schema":
		if input == nil {
			break
		}
		for _, tool := range input.Tools {
			location := "tool:" + tool.Name
			switch field {
			case "tool.name":
				out = add(out, tool.Name, location)
			case "tool.title":
				out = add(out, tool.Title, location)
			case "tool.description":
				out = add(out, tool.Description, location)
			case "tool.schema":
				out = add(out, string(tool.InputSchema), location)
			}
		}
	case "resource.name", "resource.description":
		if input == nil {
			break
		}
		for _, resource := range input.Resources {
			value := resource.Name
			if field == "resource.description" {
				value = resource.Description
			}
			out = add(out, value, "resource:"+resource.Name)
		}
	case "prompt.name", "prompt.description":
		if input == nil {
			break
		}
		for _, prompt := range input.Prompts {
			value := prompt.Name
			if field == "prompt.description" {
				value = prompt.Description
			}
			out = add(out, value, "prompt:"+prompt.Name)
		}
	case "content.text":
		if input == nil {
			break
		}
		for _, content := range input.ContentText {
			out = add(out, content.Text, content.Kind+" content:"+content.Name)
		}
	case "finding.rule", "finding.title", "finding.severity", "finding.location", "finding.evidence":
		for _, finding := range findings {
			value := ""
			switch field {
			case "finding.rule":
				value = finding.RuleID
			case "finding.title":
				value = finding.Title
			case "finding.severity":
				value = string(finding.Severity)
			case "finding.location":
				value = finding.Location
			case "finding.evidence":
				value = finding.Evidence
			}
			out = add(out, value, finding.Location)
		}
	}
	return out
}
