module github.com/jsommers/someta

go 1.16

require (
	github.com/jsommers/someta/monitors v1.3.0
	github.com/shirou/gopsutil v3.21.5+incompatible
	github.com/tklauser/go-sysconf v0.3.6 // indirect
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/jsommers/someta/monitors v1.3.0 => ./monitors
