deploy:
	gcloud run deploy --image gcr.io/`gcloud config get-value project`/simpleauthweb01 --platform managed

build:
	gcloud builds submit --tag gcr.io/`gcloud config get-value project`/simpleauthweb01

docker-run:
	sudo docker run -it --rm -p 8080:8080 simpleauthweb01

docker-build:
	sudo docker build . -t simpleauthweb01

local-build:
	CGO_ENABLED=0 go build -o server

local-run:
	./server
