# AnVir Next interface

Mode: Operate. This is a native Windows utility; familiar controls, keyboard access, compact tables and readable measurements take priority over decoration.

- Use Segoe UI scaled to the system DPI, with a slightly larger summary. Follow Windows AppsUseLightTheme at startup and on theme notifications. Dark surfaces use #202020/#1B1B1B with #EEEEEE text; native system colors govern light/high-contrast surfaces, selection and focus.
- Draw notification icons at the actual taskbar icon size. Temperature is red and memory teal. CPU has light-blue physical-core columns on black with a smaller total number at 50% opacity. Network shows receive and send for active external physical adapters. Disk shows read and write on a shared scale. The tooltip shows device busy time, separate read/write rates and the busiest processes in each direction.
- The initial window is 1180 by 780 pixels, resizable, with per-monitor DPI support. Tables fill available space; measurements stay aligned in numeric columns.
- Show overall activity above four native tabs: Processes, Autostart, Sensors and Rules. Filters and actions live adjacent to the relevant table. The selected process's complete command line is selectable and copyable below the table.
- Autostart uses a source-navigation tree on the left and entries on the right, with counts, persistent expanded groups and application icons. Row context menus expose the same guarded actions as the toolbar.
- Preserve process selection/scroll on refresh. Pause automatic row reordering while the pointer or context menu is inside the table; measurements continue updating. Explicit column sorting/search still acts immediately.
- Unknown or stale values display an em dash and a status explanation; they never become zero.
- Closing the window hides it to the tray. Exit is an explicit tray action. A single instance owns the notification icons.
- Update the process table when visible and sample separately for saved rules. Cache argument tails only while the Processes tab is visible. Collect process disk activity while that tab or the disk tooltip is open. Tooltip-only monitoring uses a compact process snapshot.

Session direction: code first, based on the user's request to begin. No standing image-generation workflow preference is inferred or stored.
