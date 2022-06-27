# SecurityScorer  
  
SecurityScorer is a service in [BIECO](https://www.bieco.org/) methodology.

Its purpose is to parse and process the output of other tools, that are
responsible for threat evaluation and analysism and some additional user input,
the metadata, with details specific for each tool.
Based on this information, it uses an appropriate inner module for a given tool
to calculate a numerical value - a security score.
For details, please refer to BIECO WP7 deliverables, especially D7.3.

At the moment, only GraphWalker's results are supported.

## How to use the API

Install [pipenv](https://pipenv.pypa.io/en/latest/) and run:

```pipenv install --keep-outdated```

And then:

```pipenv run uvicorn security_scorer:app```

An example request is provided in the root folder of the project.

## How to run tests

Simple:

```tox```
