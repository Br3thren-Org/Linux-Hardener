#!/usr/bin/env bash
# aws.sh — AWS EC2 provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Uses EBS detach/attach strategy instead of rescue mode.
# Requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, aws CLI.

: "${AWS_REGION:=us-east-1}"

# Internal state for the helper instance
declare -g _AWS_HELPER_INSTANCE_ID=""
declare -g _AWS_ORIGINAL_VOLUME_ID=""
declare -g _AWS_ORIGINAL_DEVICE=""
declare -g _AWS_AVAILABILITY_ZONE=""

_aws_cmd() {
    aws --region "${AWS_REGION}" --output json "$@"
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-t3.micro}"
    local image="${3}"
    local location="${4:-}"
    local ssh_key_name="${5:-}"

    if [[ -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        printf 'ERROR: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set\n' >&2
        return 1
    fi

    if ! command -v aws &>/dev/null; then
        printf 'ERROR: aws CLI is required for AWS provider\n' >&2
        return 1
    fi

    # Resolve AMI from image name
    local ami_id
    ami_id="$(_aws_resolve_ami "${image}")" || return 1

    local run_args=(
        ec2 run-instances
        --image-id "${ami_id}"
        --instance-type "${server_type}"
        --count 1
        --tag-specifications "$(printf 'ResourceType=instance,Tags=[{Key=Name,Value=%s}]' "${name}")"
    )

    if [[ -n "${ssh_key_name}" ]]; then
        run_args+=(--key-name "${ssh_key_name}")
    fi

    local response
    response="$(_aws_cmd "${run_args[@]}")" || return 1

    local instance_id
    instance_id="$(printf '%s' "${response}" | jq -r '.Instances[0].InstanceId')"

    # Wait for running
    _aws_cmd ec2 wait instance-running --instance-ids "${instance_id}" || return 1

    # Get public IP
    local describe
    describe="$(_aws_cmd ec2 describe-instances --instance-ids "${instance_id}")" || return 1

    local public_ip
    public_ip="$(printf '%s' "${describe}" | \
        jq -r '.Reservations[0].Instances[0].PublicIpAddress')"

    _AWS_AVAILABILITY_ZONE="$(printf '%s' "${describe}" | \
        jq -r '.Reservations[0].Instances[0].Placement.AvailabilityZone')"

    printf '%s|%s' "${instance_id}" "${public_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # AWS rescue mode: stop instance, detach root EBS, create helper, attach volume to helper

    # 1. Stop the original instance
    _aws_cmd ec2 stop-instances --instance-ids "${server_id}" >/dev/null || return 1
    _aws_cmd ec2 wait instance-stopped --instance-ids "${server_id}" || return 1

    # 2. Find root volume
    local volumes
    volumes="$(_aws_cmd ec2 describe-instances --instance-ids "${server_id}")" || return 1

    _AWS_ORIGINAL_VOLUME_ID="$(printf '%s' "${volumes}" | \
        jq -r '.Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId')"
    _AWS_ORIGINAL_DEVICE="$(printf '%s' "${volumes}" | \
        jq -r '.Reservations[0].Instances[0].BlockDeviceMappings[0].DeviceName')"

    # 3. Detach root volume
    _aws_cmd ec2 detach-volume --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" >/dev/null || return 1
    _aws_cmd ec2 wait volume-available --volume-ids "${_AWS_ORIGINAL_VOLUME_ID}" || return 1

    # 4. Launch a helper instance (Amazon Linux 2, same AZ)
    local helper_ami
    helper_ami="$(_aws_cmd ec2 describe-images \
        --owners amazon \
        --filters 'Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2' \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text)" || return 1

    local helper_response
    helper_response="$(_aws_cmd ec2 run-instances \
        --image-id "${helper_ami}" \
        --instance-type t3.micro \
        --placement "AvailabilityZone=${_AWS_AVAILABILITY_ZONE}" \
        --count 1 \
        --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=luks-helper}]')" || return 1

    _AWS_HELPER_INSTANCE_ID="$(printf '%s' "${helper_response}" | jq -r '.Instances[0].InstanceId')"
    _aws_cmd ec2 wait instance-running --instance-ids "${_AWS_HELPER_INSTANCE_ID}" || return 1

    # 5. Attach original volume to helper as /dev/xvdf
    _aws_cmd ec2 attach-volume \
        --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" \
        --instance-id "${_AWS_HELPER_INSTANCE_ID}" \
        --device /dev/xvdf >/dev/null || return 1

    sleep 10

    # Get helper's public IP
    local helper_describe
    helper_describe="$(_aws_cmd ec2 describe-instances \
        --instance-ids "${_AWS_HELPER_INSTANCE_ID}")" || return 1

    local helper_ip
    helper_ip="$(printf '%s' "${helper_describe}" | \
        jq -r '.Reservations[0].Instances[0].PublicIpAddress')"

    # Return IP of helper instance (engine will run there)
    printf 'none'
    # Caller should SSH to helper_ip — store it for later
    printf '\n%s' "${helper_ip}" # second line: helper IP
}

provider_exit_rescue() {
    local server_id="${1}"

    # Detach volume from helper
    _aws_cmd ec2 detach-volume --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" >/dev/null || return 1
    _aws_cmd ec2 wait volume-available --volume-ids "${_AWS_ORIGINAL_VOLUME_ID}" || return 1

    # Reattach to original instance
    _aws_cmd ec2 attach-volume \
        --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" \
        --instance-id "${server_id}" \
        --device "${_AWS_ORIGINAL_DEVICE}" >/dev/null || return 1

    sleep 5

    # Terminate helper
    if [[ -n "${_AWS_HELPER_INSTANCE_ID}" ]]; then
        _aws_cmd ec2 terminate-instances \
            --instance-ids "${_AWS_HELPER_INSTANCE_ID}" >/dev/null || true
    fi
}

provider_reboot() {
    local server_id="${1}"

    _aws_cmd ec2 start-instances --instance-ids "${server_id}" >/dev/null || return 1
    _aws_cmd ec2 wait instance-running --instance-ids "${server_id}" || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _aws_cmd ec2 terminate-instances --instance-ids "${server_id}" >/dev/null || return 1

    # Clean up helper if still running
    if [[ -n "${_AWS_HELPER_INSTANCE_ID}" ]]; then
        _aws_cmd ec2 terminate-instances \
            --instance-ids "${_AWS_HELPER_INSTANCE_ID}" >/dev/null 2>&1 || true
    fi
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_aws_cmd ec2 describe-instances --instance-ids "${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local state
    state="$(printf '%s' "${response}" | \
        jq -r '.Reservations[0].Instances[0].State.Name')"

    case "${state}" in
        running)    printf 'running' ;;
        stopped)    printf 'stopped' ;;
        terminated) printf 'stopped' ;;
        *)          printf '%s' "${state}" ;;
    esac
}

_aws_resolve_ami() {
    local image="${1}"

    local filter_name=""
    local owner=""
    case "${image}" in
        debian-12)
            filter_name="debian-12-amd64-*"
            owner="136693071363"
            ;;
        ubuntu-24.04)
            filter_name="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
            owner="099720109477"
            ;;
        rocky-9)
            filter_name="Rocky-9-EC2-Base-*.x86_64-*"
            owner="792107900819"
            ;;
        alma-9)
            filter_name="AlmaLinux OS 9*x86_64*"
            owner="764336703387"
            ;;
        *)
            printf 'ERROR: Unknown image for AWS: %s\n' "${image}" >&2
            return 1
            ;;
    esac

    _aws_cmd ec2 describe-images \
        --owners "${owner}" \
        --filters "Name=name,Values=${filter_name}" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text || return 1
}
