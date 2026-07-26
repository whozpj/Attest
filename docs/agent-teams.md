# Agent Teams (Claude Code, experimental)

Source: https://code.claude.com/docs/en/agent-teams

## What it is

Agent teams let multiple Claude Code sessions work together: one session is
the **team lead** (coordinates, assigns tasks, synthesizes results), and
**teammates** are separate sessions, each with its own context window, that
communicate directly with each other (not just back to the lead).

This differs from **subagents**, which only report results back to the main
agent and can't talk to each other or self-coordinate.

| | Subagents | Agent teams |
|---|---|---|
| Context | Own window; results return to caller | Own window; fully independent |
| Communication | Report to main agent only | Teammates message each other directly |
| Coordination | Main agent manages all work | Shared task list, self-coordination |
| Token cost | Lower | Higher (each teammate is a full session) |

## Enabling

Disabled by default. Enabled for this project via
`.claude/settings.local.json`:

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

Without this, no team is set up, no team directories are written, and Claude
won't spawn or propose teammates.

## Usage

Just describe the task and desired roles in natural language, e.g.:

> Spawn three teammates to explore this from different angles: one on UX,
> one on technical architecture, one playing devil's advocate.

Claude populates a shared task list, spawns teammates, and synthesizes
findings when done. If Claude spawns subagents instead of a team, explicitly
ask for an agent team.

Key interactions (in-process mode, default):
- Agent panel below the prompt lists teammates; ↑/↓ select, Enter opens a
  teammate's transcript to message it directly, Esc interrupts its turn.
- `x` on a selected teammate stops it.
- Ctrl+T toggles the task list.
- Ask the lead to "shut down" a named teammate to end it gracefully.

Specify teammate count/model explicitly if desired:
> Spawn 4 teammates to refactor these modules in parallel. Use Sonnet for each.

Teammates don't inherit the lead's `/model` by default — set **Default
teammate model** in `/config`, or they inherit the lead's effort level.

Require plan approval for risky work:
> Spawn an architect teammate to refactor the auth module. Require plan
> approval before they make any changes.

## Architecture

| Component | Role |
|---|---|
| Team lead | Main session; spawns teammates, coordinates work |
| Teammates | Separate Claude Code instances working assigned tasks |
| Task list | Shared work items (pending / in progress / completed, with dependencies) |
| Mailbox | Per-agent JSON inbox for messaging: `~/.claude/teams/{team-name}/inboxes/{agent-name}.json` |

Team/task state stored locally under a session-derived name
(`session-<8-char-session-id>`):
- Team config: `~/.claude/teams/{team-name}/config.json` (removed when session ends)
- Task list: `~/.claude/tasks/{team-name}/` (persists locally, survives resume, never uploaded)

Don't hand-edit the team config — it's overwritten on state updates. There is
no project-level team config file (a `.claude/teams/teams.json` in-repo is
just an ordinary file, not recognized as config).

Teammates can be spawned from a named [subagent](https://code.claude.com/docs/en/sub-agents)
definition (project/user/plugin/CLI scope) to reuse a role (e.g.
`security-reviewer`) across both subagent and teammate use. Note: a
subagent's `skills` and `mcpServers` frontmatter fields are ignored when run
as a teammate — teammates load skills/MCP servers the normal way (project +
user settings).

## Permissions

Teammates start with the lead's permission mode (including
`--dangerously-skip-permissions` if the lead has it); can't set per-teammate
mode at spawn time, only after. Teammate permission prompts surface in the
**lead's** session. A teammate can't approve prompts or relay consent on your
behalf — the classifier in auto mode treats a relayed "approval" as untrusted
input, not confirmation from you. Plan approval is the one exception: the
lead itself grants/rejects a teammate's plan without prompting you.

## Context & communication

Teammates load the same project context as a normal session (CLAUDE.md, MCP
servers, skills) plus the lead's spawn prompt — **not** the lead's
conversation history. So: give teammates enough task-specific context in the
spawn prompt.

- Messages between agents are delivered automatically.
- Teammates auto-notify the lead when they finish/go idle (or fail, since v2.1.198).
- Task claiming uses file locking to avoid races.
- To message a specific teammate, address it by name (ask the lead to name
  teammates predictably at spawn time).

## Token cost

Significantly higher than a single session — costs scale per teammate.
Worth it for research/review/new-feature work; not for routine/sequential
tasks.

## Best practices

- **Team size**: start with 3–5 teammates; ~5–6 tasks per teammate keeps
  everyone busy without too much coordination overhead.
- **Task granularity**: not so small that coordination overhead dominates,
  not so large that a teammate runs unchecked for a long time.
- **Avoid file conflicts**: each teammate should own a distinct set of files.
- **Monitor & steer**: don't let a team run unattended for long.
- Good first use cases: parallel PR review (assign each teammate a distinct
  lens — security/performance/tests), or competing-hypothesis debugging
  (multiple teammates investigate + actively try to disprove each other's
  theories, converging on the true root cause faster than sequential
  investigation).

## Known limitations (experimental)

- **No session resumption** for in-process teammates: `/resume`/`/rewind`
  don't restore them; the lead may try messaging teammates that no longer
  exist — tell it to respawn.
- **Task status can lag** — teammates sometimes fail to mark tasks complete,
  blocking dependents; check manually if something looks stuck.
- **Shutdown can be slow** — teammates finish current tool call/request first.
- **One team per session**, scoped to that session; no sharing across sessions.
- **No nested teams** — only the lead can spawn/manage teammates.
- **No background subagents from in-process teammates** — a teammate's own
  subagents run in the foreground only.
- **Lead is fixed** for the session's lifetime — can't promote a teammate to lead.
- **Permissions fixed at spawn** to the lead's mode; changeable only after.
- **Split panes** (tmux / iTerm2 `it2` CLI) not supported in VS Code's
  integrated terminal, Windows Terminal, or Ghostty — default in-process mode
  works everywhere.

## Display mode (optional)

Default is `"in-process"` (all teammates in main terminal, arrow keys +
Enter to view/message). Split-pane mode shows each teammate in its own pane
(requires tmux or iTerm2 + `it2` CLI). Configure globally in
`~/.claude/settings.json`:

```json
{ "teammateMode": "auto" }
```

or per-session: `claude --teammate-mode auto` (experimental flag, not in
`--help`).

Values: `"in-process"` (default), `"auto"` (split panes if already in
tmux/iTerm2+it2, else in-process), `"tmux"`, `"iterm2"` (v2.1.186+).
