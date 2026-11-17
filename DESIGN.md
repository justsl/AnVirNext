# AnVir Next interface

Mode: Operate. This is a native Windows utility; familiar controls, keyboard access, compact tables and readable measurements take priority over decoration.

- Use Segoe UI scaled to the system DPI, with a slightly larger summary. Native Windows colors govern surfaces, text, selection and focus.
- Draw notification icons at the actual taskbar icon size. Temperature is red, CPU activity purple and memory teal, with readable numerical values. Network is violet and disk amber, with recent-activity graphs.
- The initial window is 1180 by 780 pixels, resizable, with per-monitor DPI support. Tables fill available space; measurements stay aligned in numeric columns.
- Show overall activity above four native tabs: Processes, Autostart, Sensors and Rules. Filters and actions live adjacent to the relevant table. The selected process's complete command line is selectable and copyable below the table.
- Unknown or stale values display an em dash and a status explanation; they never become zero.
- Closing the window hides it to the tray. Exit is an explicit tray action. A single instance owns the notification icons.
- No decorative animation, web runtime, network services or continuous painting. Sample processes only for a visible, non-minimized Processes tab or saved-rule enforcement. Read command-line details on selection.

Session direction: code first, based on the user's request to begin. No standing image-generation workflow preference is inferred or stored.
