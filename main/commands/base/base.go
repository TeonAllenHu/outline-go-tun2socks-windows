package base

// BaseCommand is the base command of all commands
var BaseCommand *Command

func init() {
	BaseCommand = &Command{
		UsageLine: CommandEnv.Exec,
		Long:      "The base command",
	}
}

// RegisterCommand register a command to BaseCommand
func RegisterCommand(cmd *Command) {
	BaseCommand.Commands = append(BaseCommand.Commands, cmd)
}
