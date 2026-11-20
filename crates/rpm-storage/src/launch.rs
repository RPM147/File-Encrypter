//! Shared GUI/Explorer launch-intent parsing.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchTab {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiLaunchIntent {
    pub tab: Option<LaunchTab>,
    pub paths: Vec<String>,
}

/// Interpret bare paths or `--gui-encrypt`/`--gui-decrypt` flags passed to the GUI binary.
pub fn parse_gui_launch_args(args: &[String]) -> GuiLaunchIntent {
    if args.is_empty() {
        return GuiLaunchIntent {
            tab: None,
            paths: Vec::new(),
        };
    }

    match args[0].as_str() {
        "--gui-encrypt" => GuiLaunchIntent {
            tab: Some(LaunchTab::Encrypt),
            paths: args[1..]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect(),
        },
        "--gui-decrypt" => GuiLaunchIntent {
            tab: Some(LaunchTab::Decrypt),
            paths: args[1..]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect(),
        },
        _ => {
            let paths: Vec<String> = args
                .iter()
                .filter(|s| !s.is_empty() && !s.starts_with('-'))
                .cloned()
                .collect();
            if paths.is_empty() {
                GuiLaunchIntent {
                    tab: None,
                    paths: Vec::new(),
                }
            } else if paths.iter().all(|p| p.to_lowercase().ends_with(".vault")) {
                GuiLaunchIntent {
                    tab: Some(LaunchTab::Decrypt),
                    paths,
                }
            } else {
                GuiLaunchIntent {
                    tab: Some(LaunchTab::Encrypt),
                    paths,
                }
            }
        }
    }
}
