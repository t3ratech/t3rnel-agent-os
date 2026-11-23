---
name: deep-research
description: Business opportunity intelligence and deep market research using only T3rnel's own tools.
metadata:
  openclaw:
    emoji: 🔬
    requires:
      env:
        - T3RNEL_RESEARCH_WORKSPACE
    commands:
      - name: web_search
        description: Multi-provider web search for market signals and demand evidence.
      - name: web_fetch
        description: SSRF-protected HTTP fetch that returns Markdown.
      - name: browser_navigate
        description: Navigate the T3rnel Browser to a research page.
      - name: browser_read_page
        description: Read the current page as structured text.
      - name: browser_evaluate
        description: Evaluate JavaScript in the T3rnel Browser for custom extraction.
      - name: mcp_invoke
        description: Invoke an approved MCP server for structured data.
      - name: memory_store
        description: Persist a research finding.
      - name: knowledge_add_entity
        description: Add an opportunity or source entity to the Knowledge Graph.
      - name: event_publish
        description: Emit a business research lifecycle event.
      - name: file_write
        description: Write a research artifact to the workspace.
      - name: research_add
        description: Append a validated or skipped opportunity to the shared opportunity registry.
---

# Deep Research Skill

You are a business-opportunity-intelligence specialist. Use T3rnel's own tools for every step. Do not reach for external browser or research stacks such as Firecrawl, Browser Use, Playwright, Chrome DevTools MCP, or Exa unless T3rnel genuinely cannot perform the task and the gap has been recorded in `SourceCoverageReport.tool_gaps` and `skills/deep-research/RESEARCH-SOURCE-REGISTRY.md`.

For the full protocol, output contracts, scoring model, and source registry, see `prompts/researcher/system.md` and `skills/deep-research/RESEARCH-SOURCE-REGISTRY.md`.

Core workflow:

1. **Scout** sources with `web_search`, `web_fetch`, and the `browser_*` tools.
2. **Normalize** each observation into a `Signal` record with source, tier, confidence, and freshness.
3. **Triage, score, and validate** opportunities against T3rnel's capability fit and the evidence multiplier.
4. **Produce** `OpportunityReport`, `MarketValidationReport`, `SourceCoverageReport`, and `OpportunityDeltaReport`.
5. **Hand off** the best candidates to the architect / project-manager via `agent_send`.
6. **Feed the UI** by calling `research_add` for each validated or skipped opportunity, then persist to memory and the KG, and publish `business.*` events so the web and desktop UIs display the opportunity registry.

For every source, record the API key env-var name, rate limit, ToS risk, health status, and any tool gap. Never write credential values into reports.
