# Copyright 2019 Decipher Technology Studios
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: coverage
coverage: test
	@echo "--> Opening coverage..."
	@CGO_ENABLED=0 GO111MODULE=on go tool cover -html=./coverage/c.out

.PHONY: test
test: vendor
	@echo "--> Running tests..."
	@CGO_ENABLED=0 GO111MODULE=on go test -v --coverprofile=./coverage/c.out --mod=vendor ./...

.PHONY: vendor
vendor:
	@echo "--> Vendoring dependencies..."
	@CGO_ENABLED=0 GO111MODULE=on go mod vendor
