module intel/isecl/shub

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.10
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/clients/v3 v3.0.0
	intel/isecl/lib/common/v3 v3.0.0
)

replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.0.0
replace intel/isecl/lib/clients/v3 => github.com/intel-secl/clients/v3 v3.0.0
