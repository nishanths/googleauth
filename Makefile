PROJECT_ID := fieldplayground

.PHONY: all
all: clean go

.PHONY: deploy
deploy:
	gcloud --quiet --project $(PROJECT_ID) app deploy -v 1 app.yaml

.PHONY: go
go:
	@go version
	go build -mod=vendor -o=main

.PHONY: dev
dev: go
	./main

.PHONY: clean
clean:
	rm -f main
