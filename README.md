# Untron Circuits
This repository holds the circuits that will be used for the Untron.finance project

## Setup

Clone the repository and then run
```
go mod tidy
```

To install dependencies

## Development

For development, use the test package directly

To test single circuit use 
```
go run single/main.go -blocks=input/input.json -srs=input/srs.json
```

To test composite circuit use
```
go run composite/main.go -blocks=input/input.json -srs=input/srs.json
```

The blocks and SRS list used were created using [Tron light client](https://github.com/ultrasoundlabs/tron-light-client)