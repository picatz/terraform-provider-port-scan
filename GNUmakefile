default: build

# Build binary plugin
.PHONY: build
build:
	go build -o terraform-provider-port

# Initeralize terraform
.PHONY: tf/init
tf/init:
	terraform init

# Run terraform plan
.PHONY: tf/plan
tf/plan:
	terraform plan

# Run terraform apply
.PHONY: tf/apply
tf/apply:
	terraform apply -auto-approve

# Run acceptance tests
.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

# Install the plugin
.PHONY: install
install:
	go install