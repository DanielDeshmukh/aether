# UI Context

## Theme

The UI is dark-first and cinematic, built around a Lamborghini-inspired operator-console aesthetic rather than a neutral SaaS dashboard. Surfaces are near-black, typography is uppercase and high-tracking in many headings, and gold is the primary action and status accent. Panels, badges, and buttons often use chamfered shapes instead of rounded cards.

## Colors

The project already defines root tokens in `frontend/src/index.css`, but many components still mix those tokens with Tailwind utility colors and inline hex values.

| Role | CSS Variable | Value |
| --- | --- | --- |
| Page background | `--aether-black` | `#050505` |
| Primary panel | `--aether-panel` | `#0d0d0d` |
| Secondary panel | `--aether-panel-2` | `#111111` |
| Primary accent | `--aether-gold` | `#FFC107` |
| Accent dark | `--aether-gold-deep` | `#917300` |
| Primary text | `--aether-ink` | `#f5f1df` |
| Muted text | `--aether-muted` | `#8f8a78` |
| Border accent | `--aether-line` | `rgba(212, 175, 55, 0.18)` |

Common non-token accents currently in use:

- Success and live-status green around `#00ff41`
- Error red utilities for failed states and blocked actions
- Cyan accents for remediation and PR-related actions in debrief views

## Typography

| Role | Font | Variable |
| --- | --- | --- |
| Display and dashboard text | Custom `font-lambo` Tailwind font utility | project-defined utility, not a CSS variable |
| Console and auth surfaces | `font-mono` utility | project-defined utility, not a CSS variable |
| Sidebar and some supporting text | `font-sans` utility | project-defined utility, not a CSS variable |

## Border Radius And Shapes

The visual system favors chamfered clip-path shapes over standard rounded corners.

| Context | Class |
| --- | --- |
| Large panels | `chamfer-panel` |
| Primary buttons | `chamfer-button` |
| Small badges | `chamfer-badge` |
| Some auth inputs/cards | conventional `rounded-xl` or `rounded-2xl` still appear |

## Component Library

There is no external component library such as shadcn/ui in the current codebase. UI is hand-built from React components, Tailwind classes, custom clip-path helpers, and Framer Motion for selective animation.

## Layout Patterns

- Landing page: top nav plus stacked storytelling sections such as `Hero`, `Capabilities`, `TechOverview`, `WhyAether`, and `Vision`.
- Authenticated home: two-column operator workspace with scan controls and live console on the left, telemetry sidebar on the right.
- Dashboard: responsive card grid with recent persisted scans and a debrief drill-down path.
- Scan debrief: split layout with high-level risk summary, remediation steps, finding cards, and persisted strategy trace.
- Modal pattern: telemetry report download uses a centered fullscreen overlay dialog.

## UI Component Map

- `Navbar`, `Hero`, `Capabilities`, `TechOverview`, `WhyAether`, `Vision`, `Footer`
  Marketing and brand storytelling for the landing route.
- `Header`
  Authenticated top navigation with Home, Dashboard, and sign-out action.
- `InputUrl`
  Target submission, consent checkbox, legal confirmation step, and scan creation request.
- `ScanningConsole`
  Live WebSocket log stream, plan-hold resume control, and kill switch.
- `SidebarTelemetry`
  Recent scans panel and PDF download entrypoint.
- `Dashboard`
  Recent scan cards with realtime WebSocket updates.
- `ScanDetail`
  Full debrief page with verdict, findings, remediation generation, and strategy trace.
- `JoinUs`
  Google OAuth and magic-link authentication page.

## Motion

- Framer Motion is used on the authenticated home page for staged entrance transitions.
- Console logs, loading states, and remediation states also use Tailwind animation utilities like pulse, bounce, and fade/slide transitions.

## Responsive Expectations

- The dashboard and authenticated home layouts are already built with responsive grid breakpoints.
- The project definition of done requires dashboard mobile responsiveness, so changes to dashboard cards, detail panels, and telemetry overlays should preserve mobile behavior.
- When updating existing UI, preserve the dark luxury-console visual language instead of reverting to generic default SaaS styling.
