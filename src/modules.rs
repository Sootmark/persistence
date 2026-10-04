//! Kernel modules loaded at boot (`etc/modules`, `modules-load.d/*.conf`:
//! one module per line, `etc/modules` with its parameters) and modprobe's
//! configuration (`modprobe.d/*.conf`): `install` and `remove` replace
//! loading or unloading a module with a shell command, run as root
//! whenever it is asked for, which rootkits use to stay loaded.

use crate::text::{logical_lines, split_word, Continuation};
use crate::{Detail, Entry, Kind, Parsed};

/// Read a modules list: `etc/modules` or a `modules-load.d` file.
pub(crate) fn load_list(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in logical_lines(text, Continuation::Shell) {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let mut entry = Entry::new(Kind::ModulesLoad, number, Detail::KernelModule);
        entry.command = Some(line.to_owned());
        parsed.entries.push(entry);
    }
    parsed
}

/// Read a `modprobe.d` file: one entry per directive.
pub(crate) fn modprobe(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in logical_lines(text, Continuation::Shell) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (directive, rest) = split_word(line);
        let (module, arguments) = split_word(rest);
        if module.is_empty() {
            parsed.problem(number, "a directive without a module");
            continue;
        }
        let runs = matches!(directive, "install" | "remove") && !arguments.is_empty();
        let detail = Detail::ModprobeDirective {
            directive: directive.to_owned(),
            module: module.to_owned(),
            arguments: arguments.to_owned(),
        };
        let mut entry = Entry::new(Kind::Modprobe, number, detail);
        if runs {
            entry.user = Some("root".to_owned());
            entry.command = Some(arguments.to_owned());
        }
        parsed.entries.push(entry);
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_lists() {
        let parsed = load_list("# /etc/modules\nloop\n; comment\nlp io=0x378\n");
        let modules: Vec<_> = parsed
            .entries
            .iter()
            .map(|e| e.command.as_deref())
            .collect();
        assert_eq!(modules, [Some("loop"), Some("lp io=0x378")]);
    }

    #[test]
    fn modprobe_directives() {
        let parsed = modprobe(
            "blacklist pcspkr\ninstall usb-storage /bin/true\ninstall nfs /usr/local/sbin/x; /sbin/modprobe --ignore-install nfs\noptions\n",
        );
        assert_eq!(parsed.problems, ["line 4: a directive without a module"]);
        let commands: Vec<_> = parsed
            .entries
            .iter()
            .map(|e| e.command.as_deref())
            .collect();
        assert_eq!(
            commands,
            [
                None,
                Some("/bin/true"),
                Some("/usr/local/sbin/x; /sbin/modprobe --ignore-install nfs")
            ]
        );
    }
}
