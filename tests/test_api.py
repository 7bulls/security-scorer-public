import pytest


class TestApi:
    @pytest.mark.parametrize(
        "is_warned,errored,request_json,"
        + "warning_or_error_messages,status_code,expected_scores",
        [
            (
                True,
                False,
                pytest.lazy_fixture("example_request_with_graphwalker"),
                [
                    "Warning: not all tests included in graphwalker output were defined"
                    + " in .yaml input file. Please make sure that you spelled all"
                    + " the names correctly in your .yaml file"
                ],
                200,
                [0.0, 21.0, 0.0, 0.0, 5.0, 0.0],
            ),
            (
                False,
                True,
                pytest.lazy_fixture(
                    "example_request_with_graphwalker_misspelled_impact"
                ),
                [
                    "There is a field missing in ('claims', 'claim_c49') Missing"
                    + " field is impact Make sure that you spelled all the "
                    + "names correctly in your .yaml file"
                ],
                400,
                [0.0, 21.0, 0.0, 0.0, 5.0, 0.0],
            ),
            (
                False,
                True,
                pytest.lazy_fixture(
                    "example_request_with_graphwalker_misspelled_test_name"
                ),
                [
                    "MisspelledTestName is not among test results from the"
                    + " graphwalker tool. Please make sure that you spelled"
                    + " all the names correctly in .yaml file"
                ],
                400,
                [0.0, 21.0, 0.0, 0.0, 5.0, 0.0],
            ),
            (
                True,
                False,
                pytest.lazy_fixture(
                    "example_request_with_graphwalker_misspelled_component_claim"
                ),
                [
                    "Warning: not all tests included in graphwalker output were defined"
                    + " in .yaml input file. Please make sure that you spelled all"
                    + " the names correctly in your .yaml file",
                    "Not all of the components defined in system definition "
                    + "are used in claims. Please make sure that you spelled "
                    + "all the names correctly in your .yaml file.",
                ],
                200,
                [0.0, 21.0, 0.0, 0.0, 0.0, 0.0],
            ),
            (
                True,
                False,
                pytest.lazy_fixture(
                    "example_request_with_graphwalker_misspelled_component_definition"
                ),
                [
                    "Warning: not all tests included in graphwalker output were defined"
                    + " in .yaml input file. Please make sure that you spelled all"
                    + " the names correctly in your .yaml file",
                    "Not all of the components defined in system definition "
                    + "are used in claims. Please make sure that you spelled "
                    + "all the names correctly in your .yaml file.",
                ],
                200,
                [0.0, 21.0, 0.0, 0.0, 0.0, 0.0],
            ),
            (
                False,
                True,
                pytest.lazy_fixture(
                    "example_request_with_graphwalker_misspelled_vulnerability"
                ),
                [
                    "misspelled_vulnerability is not in system definition."
                    + " Please make sure that you spelled"
                    + " all the names correctly in .yaml file"
                ],
                400,
                [0.0, 21.0, 0.0, 0.0, 5.0, 0.0],
            ),
        ],
    )
    def test_estimate_risk(
        self,
        client,
        recwarn,
        is_warned,
        errored,
        request_json,
        warning_or_error_messages,
        status_code,
        expected_scores,
    ):
        # given
        url = "/estimate_risk"

        eps = 0.1
        expected_scores = expected_scores

        # when
        response = client.post(url, json=request_json)

        # then
        assert response.status_code == status_code
        if errored:
            assert response.json() == warning_or_error_messages[0]
        else:
            assert "scores" in response.json()
            assert isinstance(response.json()["scores"], dict)
            assert all(
                [
                    abs(score - expected_score) < eps
                    for score, expected_score in zip(
                        response.json()["scores"].values(), expected_scores
                    )
                ]
            )
        assert bool(len(recwarn)) == is_warned
        if is_warned:
            assert all(
                [
                    issubclass(w.category, UserWarning) and w.message.args[0] == message
                    for w, message in zip(
                        recwarn, warning_or_error_messages, strict=True
                    )
                ]
            )
