import base64
from enum import Enum
from warnings import warn

import yaml
from defusedxml import ElementTree
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

app = FastAPI()


# NOTE: bytes in base64 encoding
class ToolOutputs(BaseModel):
    graphwalker: bytes | None
    fuzzing_tool: bytes | None


class SecurityProperty(str, Enum):
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    AUTHORIZATION = "authorization"
    AUTHENTICATION = "authentication"
    NON_REPUDIATION = "non_repudiation"


class ComponentDefinition(BaseModel):
    sensitivity: float


class VulnerabilityDefinition(BaseModel):
    reference: str
    impact: float
    tests: list[str]


class ClaimDefinition(BaseModel):
    component: str
    security_properties: list[SecurityProperty]


class PureClaimDefinition(ClaimDefinition):
    reference: str
    impact: float
    tests: list[str]


class VulnerabilityClaimDefinition(ClaimDefinition):
    vulnerabilities: list[str]


class SystemDefinition(BaseModel):
    components: dict[str, ComponentDefinition]
    vulnerabilities: dict[str, VulnerabilityDefinition]
    claims: dict[str, PureClaimDefinition | VulnerabilityClaimDefinition]


# NOTE: bytes in base64 encoding
class RiskMetadata(BaseModel):
    # this should parse as SystemDefinition after decoding
    blob: bytes | None


class RiskDetails(BaseModel):
    metadata: RiskMetadata
    tool_outputs: ToolOutputs


class RiskScores(BaseModel):
    confidentiality: float = 0.0
    integrity: float = 0.0
    availability: float = 0.0
    authorization: float = 0.0
    authentication: float = 0.0
    non_repudiation: float = 0.0


class RiskEstimation(BaseModel):
    scores: RiskScores


@app.exception_handler(ValidationError)
def validation_exception_handler(request: Request, exception: ValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content="There is a field missing in "
        + str(exception.errors()[0]["loc"][:-1])
        + " Missing field is "
        + str(exception.errors()[0]["loc"][-1])
        + " Make sure that you spelled all the names correctly in your .yaml file",
    )


@app.exception_handler(AttributeError)
def attribute_exception_handler(request: Request, exception: AttributeError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=exception.args[0],
    )


@app.post("/estimate_risk", response_model=RiskEstimation)
async def estimate_risk(risk_details: RiskDetails) -> RiskEstimation:
    # TODO: make it work with fuzzing_tool as well
    scores = calculate_scores(
        SystemDefinition(
            **yaml.safe_load(base64.decodebytes(risk_details.metadata.blob))
        ),
        base64.decodebytes(risk_details.tool_outputs.graphwalker),
    )
    return RiskEstimation(scores=scores)


# mapping test name to likelihood
TestsResults = dict[str, float]


def parse_graphwalker_output(graphwalker_output: str) -> TestsResults:
    results = TestsResults()
    root = ElementTree.fromstring(graphwalker_output)
    for tag in root.findall("testsuite/testcase"):
        test_name = tag.get("name")
        if len(tag) > 0:
            results[test_name] = 1.0
        else:
            results[test_name] = 0.0
    return results


SystemResults = dict[(str, str), float]
PropertyResults = dict[SecurityProperty, float]


# TODO: do more validation on system_definition
def calculate_scores(
    system_definition: SystemDefinition, graphwalker_output: str
) -> RiskScores:
    result = RiskScores()

    graphwalker_results = parse_graphwalker_output(graphwalker_output)

    system_results = SystemResults()

    # TODO Need to verify if claim_def.component in system_definition.components
    # if not probably user misspelled name of a component.
    # Misspelled component will have result = 0

    user_defined_tests = []
    components_in_claims = []
    for (claim_id, claim_def) in system_definition.claims.items():
        component_name = claim_def.component
        components_in_claims.append(component_name)
        if isinstance(claim_def, PureClaimDefinition):
            claim_likelihood = 0.0
            for test_name in claim_def.tests:
                user_defined_tests.append(test_name)
                if test_name not in graphwalker_results:
                    raise AttributeError(
                        test_name
                        + " is not among test results from "
                        + "the graphwalker tool. Please make sure that you "
                        + "spelled all the names correctly in .yaml file"
                    )
                claim_likelihood += graphwalker_results[test_name]
            claim_likelihood /= len(claim_def.tests)
            claim_risk = claim_def.impact * claim_likelihood
        elif isinstance(claim_def, VulnerabilityClaimDefinition):
            claim_risk = 0.0
            for vuln_id in claim_def.vulnerabilities:
                if vuln_id not in system_definition.vulnerabilities:
                    raise AttributeError(
                        vuln_id
                        + " is not in system definition. "
                        + "Please make sure that you spelled "
                        + "all the names correctly in .yaml file"
                    )
                vuln_def = system_definition.vulnerabilities[vuln_id]
                vuln_likelihood = 0.0
                for test_name in vuln_def.tests:
                    user_defined_tests.append(test_name)
                    if test_name not in graphwalker_results:
                        raise AttributeError(
                            test_name
                            + " is not among test results from "
                            + "the graphwalker tool. Please make sure that you "
                            + "spelled all the names correctly in .yaml file"
                        )
                    vuln_likelihood += graphwalker_results[test_name]
                vuln_likelihood /= len(vuln_def.tests)
                vuln_risk = vuln_def.impact * vuln_likelihood
                if vuln_risk > claim_risk:
                    claim_risk = vuln_risk
        else:
            raise Exception()  # should never happen
        for property in claim_def.security_properties:
            key = (property, component_name)
            current_component_property_risk = system_results.get(key, 0.0)
            if claim_risk > current_component_property_risk:
                system_results[key] = claim_risk

    if any([i not in user_defined_tests for i in graphwalker_results.keys()]):
        warn(
            "Warning: not all tests included in graphwalker output"
            + " were defined in .yaml input file. Please make sure "
            + "that you spelled all the names correctly in your .yaml file"
        )
    if not list(system_definition.components.keys()) == components_in_claims:
        warn(
            "Not all of the components defined in system definition "
            + "are used in claims. Please make sure that you spelled "
            + "all the names correctly in your .yaml file."
        )

    for property in SecurityProperty:
        property_name = property.value
        for (
            component_name,
            component_definition,
        ) in system_definition.components.items():
            current_property_risk = getattr(result, property_name)
            key = (property, component_name)
            proposed_property_risk = (
                system_results.get(key, 0) * component_definition.sensitivity
            )
            if proposed_property_risk > current_property_risk:
                setattr(result, property_name, proposed_property_risk)

    return result
