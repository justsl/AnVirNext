# AnVir Next interface

Mode: Operate. This is a native Windows utility; familiar controls, keyboard access, compact tables and readable measurements take priority over decoration.

- Use Segoe UI at the system DPI. Body 10–11 pt, title 18 pt, summary 14 pt.
- Main surface white; text #17212B; secondary text #52616F; dividers #DEE5EB; accent #007C91. Use system selection and focus colors in native controls.
- Notification icons are transparent, drawn at the actual taskbar icon size. CPU is cyan/teal, disk amber and network violet. Their miniature graphs carry actual recent measurements.
- The window starts at approximately 980 by 680 logical pixels, is resizable and supports 100–200% DPI. Tables fill available space; measurements stay aligned in numeric columns.
- Show overall activity above two native tabs: Processes and Sensors. Filters and process actions live adjacent to the relevant table.
- Unknown or stale values display an em dash and a status explanation; they never become zero.
- Closing the window hides it to the tray. Exit is an explicit tray action. A single instance owns the notification icons.
- No decorative animation, web runtime, network services or continuous painting. Collect process details only while their window is visible.

Session direction: code first, based on the user's request to begin. No standing image-generation workflow preference is inferred or stored.
