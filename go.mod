module github.com/openaudit/openaudit

go 1.23.0

require (
	github.com/gin-gonic/gin v1.10.1
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/gin-gonic/gin => ./third_party/gin
