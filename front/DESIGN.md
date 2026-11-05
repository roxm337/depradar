# DepRadar interface design system

A quiet, dense, data-first interface for people who triage vulnerabilities all day. It should look
like tooling a security team trusts, not like a marketing page: neutral surfaces, one accent, and
colour reserved for meaning.

## Principles

1. **Colour means something.** Neutral grays for structure. Severity (critical, high, medium, low,
   unknown) and status (ok, warn) are the only other colours. The accent (`--accent`) marks focus,
   selection, and links, never decoration.
2. **Density with air.** 13px base text, 32px controls, 46px table rows (34px in compact density).
   Group with whitespace and hairlines, not boxes inside boxes.
3. **Words over ornament.** No decorative imagery, glows, or animation without a job. Motion is
   under 200ms and respects `prefers-reduced-motion`.
4. **Every state is designed.** Loading (skeleton), empty (says what to do next), error (says what
   failed and offers retry), partial (says what is not covered), and disabled.
5. **Keyboard first.** Every action is reachable without a mouse; shortcuts are listed in the `?`
   dialog and the command palette (`⌘K`).
6. **Accessible by default.** WCAG AA contrast, visible focus, labelled controls, table semantics,
   `aria-sort`, live regions for async results. Colour is never the only signal: severity always
   carries a text label.

## Tokens (`app/globals.css`)

Always use tokens. Never hard-code a colour, radius, or shadow in a component.

| Group | Tokens |
| --- | --- |
| Surfaces | `--bg` page, `--surface` cards, `--surface-2` hover and subtle fills, `--surface-3` tracks and chips |
| Lines | `--line` hairlines, `--line-strong` inputs and emphasis |
| Text | `--text`, `--text-2`, `--text-3` (secondary, AA), `--text-4` (decoration only) |
| Accent | `--accent`, `--accent-hover`, `--accent-soft`, `--accent-text` |
| Primary action | `--primary`, `--primary-hover`, `--on-primary` (inverts in dark mode) |
| Severity | `--critical`, `--high`, `--medium`, `--low`, `--unknown`, each with a `-soft` background |
| Status | `--ok`, `--warn` and their `-soft` backgrounds |
| Shape | `--radius-sm` 4, `--radius` 6, `--radius-lg` 8; `--shadow-pop` menus, `--shadow-overlay` dialogs |
| Size | `--control` control height, `--row` table row height, `--topbar` |

Light and dark themes are both complete: `html[data-theme="dark"]` swaps the tokens. A component
that only uses tokens works in both. Density is `html[data-density="compact"]`.

Typography: Inter for interface text, JetBrains Mono (`--data`) for package names, versions,
advisory IDs, paths, and hashes. Numbers in tables use tabular figures. Headings are sentence
case; there are no uppercase or letter-spaced labels.

## Primitives (`components/workspace/ui.tsx`)

`PageHead`, `Sheet` (card), `Sev` (severity badge), `Pkg`, `StackBar`, `Empty`, `SkeletonRows`,
`Segmented`, `Switch`, `Checkbox`, `Menu` and `MenuItem` (popover menu with arrow-key support),
`Kbd`, `CopyButton`, `Drawer`, `Modal` (both trap focus and restore it on close).

Also shared: `Dialog` and `ConfirmDialog` (`drawer-dialog.tsx`, safe to stack above a drawer),
`Portal` (`portal.tsx`), `Pagination`, and `RuleEditor` (`rule-editor.tsx`).

Buttons: `.btn` with `.btn-primary` (one per view), `.btn-secondary`, `.btn-ghost`, `.btn-danger`,
`.btn-sm`. Badges: `.sev-*`, `.tag` and its variants. Forms: `.field`, `.input`, `.select`,
`.textarea`. Tables: `.table` inside `.sheet`, rows `.is-link`, `.is-selected`, `.is-active`.

## Patterns

- **Page**: `PageHead` (title, one-line description, actions) then content. No eyebrow labels.
- **Filters**: two toolbar rows above the table. The first narrows the scope (search, project,
  decision) and ends with the page's menus (views, columns, export); the second filters by state
  (status, severity chips, toggles) and ends with the result count. Active filters and a non-default
  sort are visible as chips and clearable.
- **Tables**: sticky header, sortable columns declare `aria-sort`, selection column on the left,
  paginate with the shared `Pagination` footer instead of rendering unbounded rows, advisory IDs and
  versions never wrap. A table must fit its sheet at every width: long names wrap
  (`overflow-wrap: anywhere`) and optional columns hide in priority order as the window narrows; a
  hidden column's essential fact moves into the row's subline.
- **Bulk actions**: selecting rows raises a floating bar at the bottom of the table with the count,
  the actions that apply (disabled ones say why in a title), and Clear with `Esc`.
- **Labels**: show people what was sent or what happened ("Daily digest delivered", "CI check
  completed"), never internal identifiers. Machine error codes stay verbatim in monospace. Write
  labels in sentence case in the source; CSS capitalization is only for single-word values such
  as severities, where it cannot produce Title Case.
- **Disabled controls** stay hoverable so their title can explain why they are unavailable.
- **Destructive actions** confirm in a `Modal` and say what is kept and what is removed.
- **Feedback**: toasts for outcomes, banners for standing conditions, inline messages next to the
  field that caused them.
- **Dialogs opened inside a panel** (for example a settings section, which animates with a
  transform) render through `Portal`, or the panel clips them. Long dialogs give their
  `.modal-body` the `dialog-scroll` class so the title and actions stay visible.
- **Policy rule editor**: one layer of the central gate policy. Severity is a segmented control
  ordered from least to most strict; the other rules are `Switch` rows grouped under "Always fail
  on" and "Pipelines may". Editing a project layer passes the installation rules as `floor`: the
  controls show the effective value, weaker options are disabled, and locked rules carry a "Set by
  installation policy" tag. The layer keeps only its own rules, so the floor is never copied in.
- **Decision drawer**: sections in the order a reviewer asks: why it passed or failed (verdict,
  decision reasons, violations), policy (enforced rules and every rule central policy overrode,
  shown as requested → enforced with its source), evidence (manifests, hashes, scanner versions,
  coverage, intelligence age), exceptions applied, and run identity. Verified OIDC runs are marked;
  token runs say that their repository and commit are as reported. Reports download from the stored
  decision.
- **Optional endpoints**: data from endpoints an older API build may lack (decisions, policies,
  identities) loads with a fallback, and the page shows a callout naming the rebuild command
  instead of failing the workspace.

## Keyboard

`⌘K` palette · `/` focus the page search (give the input `data-page-search`) · `?` help ·
`G` then `O` `F` `P` `K` `D` `L` `N` `S` navigate (Overview, Findings, Projects, Packages, Decisions,
Policies, Notifications, Settings) · decision rows open with `↵` · on Findings: `J` `K` move, `↵` open, `X` select,
`A` acknowledge, `Esc` clear.

## Preferences

Theme (light, dark, system), table density, and sidebar state persist in `localStorage` and are
applied to `<html>` before first paint (`components/preferences.tsx`).
