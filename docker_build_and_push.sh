#!/bin/bash

set -e

AWS_REGION=ap-northeast-2
AWS_PROFILE=deali-sandbox



ECR_REPO="964225094109.dkr.ecr.ap-northeast-2.amazonaws.com/deali-db-portal"

# ecr login
RESULT=$(aws ecr get-login-password --profile ${AWS_PROFILE} --region ${AWS_REGION} | docker login --username AWS --password-stdin 964225094109.dkr.ecr.ap-northeast-2.amazonaws.com)
if [ "$RESULT" != "Login Succeeded" ]; then
  echo "ECR에 로그인 실패 하였습니다. aws Key를 확인해 주세요. result=$RESULT"
  exit 1
fi

LATEST_IMAGE_TAG=$(aws ecr describe-images --region ${AWS_REGION} --profile ${AWS_PROFILE} --output json --repository-name deali-db-portal --query 'sort_by(imageDetails,& imagePushedAt)[*].imageTags[0]' | jq '.[]' | tail -10)
echo "최근 ECR 에 등록된 image 는 아래와 같습니다."
printf '%s\n' "${LATEST_IMAGE_TAG[@]}"
echo ""

read -p "build 할 버전을 입력해 주세요: " image_version
if [ -z "$image_version" ]; then
  echo "image version 입력 오류!"
  exit 1
fi

# set
IMAGE="${ECR_REPO}:${image_version}"

# build docker
docker build --platform linux/amd64 -t $IMAGE .

# push docker image
docker push $IMAGE

echo "SUCCESS!"