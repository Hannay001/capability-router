# Install lockkeeper with one prompt

Copy the block below and paste it into **any AI coding agent you already have**
(Claude Code, Codex, Cursor, OpenCode, Gemini CLI, Jcode, ...). The agent will
install lockkeeper, bind it to every harness it finds on your machine, and report back
in plain language. You don't need to know anything about terminals.

---

```text
Install the open-source tool "lockkeeper" on this machine, then verify it works.

Do exactly these steps:

1. Check Python 3.11+ is available (python3 --version). If not, stop and tell me.
2. Clone the repo into my home directory:
   git clone https://github.com/Hannay001/lockkeeper.git ~/lockkeeper
3. Run its installer, which also auto-detects every AI coding harness installed
   on this machine (Claude Code, Codex, Cursor, Jcode, Hermes, OpenCode,
   Gemini, or anything else) and binds lockkeeper to them automatically:
   cd ~/lockkeeper && ./install.sh
4. Build the capability index:
   ~/lockkeeper/scripts/capability-registry snapshot-runtimes
   ~/lockkeeper/scripts/capability-registry rebuild
5. Run the health check:
   ~/lockkeeper/scripts/capability-registry doctor

Then report back to me in plain language:
- which AI harnesses you found on this machine and how many skills each has,
- the total number of capabilities indexed,
- one example of a task I could route, using:
   ~/lockkeeper/scripts/capability-registry route --stdin <<'TASK'
   fix a failing test in my project
   TASK

If any step fails, show me the error and suggest the simplest fix. Do not
modify anything outside the cloned folder except the installer's own entries.
```

---

After this, `lockkeeper` is on your PATH and bound to every agent on your machine.
Ask your agent: *"run lockkeeper doctor"* any time you want to see the current state.

Prefer to choose which tools get bound? Tell your agent instead:
*"run ./install.sh with CAP_RUNTIMES=claude,codex so only those two get bound."*
