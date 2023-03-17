# OAuth2/OIDC and Basic Auth secured Rest API

## Introduction
This project aims to demonstrate how to implement two authentication mechanisms, OAuth2/OpenID Connect and Basic Authentication, in a Spring MVC Rest API. Component tests for both authentication methods are included to show that they can coexist.

The OAuth2/OIDC uses the "authorization code" flow and authentication state is tracked through HTTP session. This approach is not suitable for production-grade applications and can be replaced by other stateless approaches like JWT and encrypted cookies.

## Installation
### Prerequisites
The project requires Java 17+, you can use [SDKMan](https://sdkman.io/) to manage running multiple Java versions on your desktop.


### Running the tests

The tests include [component tests](https://martinfowler.com/articles/microservice-testing/#testing-component-in-process-diagram) for both authentication methods.

1. Clone the repository: git clone https://github.com/hernany81/spring-security-multi-auth-demo.git
2. Change directory to the cloned project: `cd spring-security-multi-auth-demo`
3. Build the project: `./gradlew check`
4. Open the test report HTML: `open build/reports/tests/test/index.html`

## Used frameworks and libraries
- Latest Spring Boot version at the time (3.0.4)
- Latest Spring Framework version at the time (6.0.2)
- Wiremock
- Mockito