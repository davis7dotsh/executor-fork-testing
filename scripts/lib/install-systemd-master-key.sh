#!/usr/bin/env bash

executor_installer_error() {
    printf '%s\n' "$1" >&2
    return 1
}

executor_paths_overlap() {
    local left=${1%/}
    local right=${2%/}

    [[ -n ${left} ]] || left=/
    [[ -n ${right} ]] || right=/
    [[ ${left} == / || ${right} == / \
        || ${left} == "${right}" \
        || ${left} == "${right}/"* \
        || ${right} == "${left}/"* ]]
}

executor_require_disjoint_paths() {
    local left=$1
    local left_description=$2
    local right=$3
    local right_description=$4

    if executor_paths_overlap "${left}" "${right}"; then
        executor_installer_error \
            "${left_description} must not overlap ${right_description}: ${right}"
        return
    fi
}

executor_write_and_sync_master_key() {
    local path=$1

    dd if=/dev/urandom of="${path}" bs=32 count=1 \
        iflag=fullblock oflag=nofollow conv=excl,fsync status=none
}

executor_sync_filesystem_path() {
    sync -f -- "$1"
}

executor_require_filesystem_sync() {
    local path=$1
    local description=$2
    local sync_status

    if executor_sync_filesystem_path "${path}"; then
        return 0
    else
        sync_status=$?
    fi
    executor_installer_error "could not sync ${description}: ${path}"
    return "${sync_status}"
}

executor_master_key_path_digest() {
    printf '%s' "$1" | sha256sum | awk '{print $1}'
}

executor_publish_master_key_recovery() {
    local recovery_path=$1
    local state=$2
    local destination_digest=$3
    local staging_name=$4
    local expected_uid=$5
    local expected_gid=$6
    local device=${7:--}
    local inode=${8:--}
    local key_digest=${9:--}
    local recovery_parent=${recovery_path%/*}
    local temporary

    if ! temporary=$(mktemp "${recovery_path}.XXXXXXXX"); then
        executor_installer_error "could not create the master key recovery record"
        return
    fi
    if ! chmod 0600 "${temporary}"; then
        if ! rm -f -- "${temporary}"; then
            executor_installer_error \
                "could not clean the unsecured master key recovery record"
        fi
        executor_installer_error "could not secure the master key recovery record"
        return
    fi
    if ! {
        printf 'executor-master-key-recovery-v1\n'
        printf 'state %s\n' "${state}"
        printf 'destination %s\n' "${destination_digest}"
        printf 'staging %s\n' "${staging_name}"
        printf 'uid %s\n' "${expected_uid}"
        printf 'gid %s\n' "${expected_gid}"
        printf 'device %s\n' "${device}"
        printf 'inode %s\n' "${inode}"
        printf 'digest %s\n' "${key_digest}"
    } > "${temporary}"; then
        if ! rm -f -- "${temporary}"; then
            executor_installer_error \
                "could not clean the unwritten master key recovery record"
        fi
        executor_installer_error "could not write the master key recovery record"
        return
    fi
    executor_require_filesystem_sync \
        "${temporary}" "the master key recovery record" || {
        local status=$?
        if ! rm -f -- "${temporary}"; then
            executor_installer_error \
                "could not clean the unsynced master key recovery record"
        fi
        return "${status}"
    }
    if ! mv -f -- "${temporary}" "${recovery_path}"; then
        if ! rm -f -- "${temporary}"; then
            executor_installer_error \
                "could not clean the unpublished master key recovery record"
        fi
        executor_installer_error "could not publish the master key recovery record"
        return
    fi
    executor_require_filesystem_sync \
        "${recovery_parent}" "the master key recovery directory"
}

executor_retire_master_key_recovery() {
    local recovery_path=$1
    local recovery_parent=${recovery_path%/*}

    if ! rm -f -- "${recovery_path}"; then
        executor_installer_error "could not retire the master key recovery record"
        return
    fi
    executor_require_filesystem_sync \
        "${recovery_parent}" "the retired master key recovery record"
}

executor_validate_master_key_recovery_file() {
    local path=$1
    local metadata file_type owner mode links size

    if ! metadata=$(LC_ALL=C stat \
        --format='%F|%u|%a|%h|%s' -- "${path}"); then
        executor_installer_error \
            "could not inspect the master key recovery record: ${path}"
        return
    fi
    IFS='|' read -r file_type owner mode links size <<< "${metadata}"
    if [[ ${file_type} != "regular file" \
        || ${owner} != "${EUID}" \
        || ${mode} != 600 \
        || ${links} != 1 \
        || ${size} -gt 4096 ]]; then
        executor_installer_error \
            "the master key recovery record has unsafe metadata: ${path}"
        return
    fi
}

executor_validate_recorded_master_key() {
    local path=$1
    local expected_device=$2
    local expected_inode=$3
    local expected_uid=$4
    local expected_gid=$5
    local expected_digest=$6
    local expected_links=$7
    local metadata file_type size links owner group mode device inode digest

    if ! metadata=$(LC_ALL=C stat \
        --format='%F|%s|%h|%u|%g|%a|%d|%i' -- "${path}"); then
        executor_installer_error "could not inspect recorded master key: ${path}"
        return
    fi
    IFS='|' read -r file_type size links owner group mode device inode <<< "${metadata}"
    if [[ ${file_type} != "regular file" \
        || ${size} != 32 \
        || ${links} != "${expected_links}" \
        || ${owner} != "${expected_uid}" \
        || ${group} != "${expected_gid}" \
        || ${mode} != 600 \
        || ${device} != "${expected_device}" \
        || ${inode} != "${expected_inode}" ]]; then
        executor_installer_error \
            "recorded master key metadata does not match recovery state: ${path}"
        return
    fi
    if ! digest=$(sha256sum -- "${path}" | awk '{print $1}'); then
        executor_installer_error "could not digest recorded master key: ${path}"
        return
    fi
    if [[ ${digest} != "${expected_digest}" ]]; then
        executor_installer_error \
            "recorded master key digest does not match recovery state: ${path}"
        return
    fi
}

executor_validate_prepared_master_key() {
    local path=$1
    local expected_device=$2
    local expected_uid=$3
    local expected_gid=$4
    local metadata file_type size links owner group mode device current_gid

    if ! metadata=$(LC_ALL=C stat \
        --format='%F|%s|%h|%u|%g|%a|%d' -- "${path}"); then
        executor_installer_error "could not inspect prepared master key: ${path}"
        return
    fi
    IFS='|' read -r file_type size links owner group mode device <<< "${metadata}"
    if ! current_gid=$(id -g); then
        executor_installer_error "could not inspect the installer group"
        return
    fi
    if [[ ${file_type} != "regular file" \
        || ${size} -gt 32 \
        || ${links} != 1 \
        || ${owner} != "${EUID}" && ${owner} != "${expected_uid}" \
        || ${group} != "${current_gid}" && ${group} != "${expected_gid}" \
        || ${mode} != 600 \
        || ${device} != "${expected_device}" ]]; then
        executor_installer_error \
            "prepared master key metadata does not match recovery state: ${path}"
        return
    fi
}

executor_recover_master_key() {
    local staging_parent=$1
    local data_dir=$2
    local path=$3
    local expected_uid=$4
    local expected_gid=$5
    local recovery_path=$6
    local destination_digest=$7
    local staging_device=$8
    local -a lines=()
    local state recorded_destination staging_name recorded_uid recorded_gid
    local recorded_device recorded_inode recorded_digest staging_dir key_tmp
    local destination_exists=false alias_exists=false destination_metadata
    local destination_device destination_inode

    if [[ ! -e ${recovery_path} && ! -L ${recovery_path} ]]; then
        return 0
    fi
    executor_validate_master_key_recovery_file "${recovery_path}" || return $?
    if ! mapfile -t lines < "${recovery_path}"; then
        executor_installer_error \
            "could not read the master key recovery record: ${recovery_path}"
        return
    fi
    if [[ ${#lines[@]} -ne 9 \
        || ${lines[0]} != executor-master-key-recovery-v1 \
        || ${lines[1]} != "state "* \
        || ${lines[2]} != "destination "* \
        || ${lines[3]} != "staging "* \
        || ${lines[4]} != "uid "* \
        || ${lines[5]} != "gid "* \
        || ${lines[6]} != "device "* \
        || ${lines[7]} != "inode "* \
        || ${lines[8]} != "digest "* ]]; then
        executor_installer_error \
            "the master key recovery record is malformed: ${recovery_path}"
        return
    fi
    state=${lines[1]#state }
    recorded_destination=${lines[2]#destination }
    staging_name=${lines[3]#staging }
    recorded_uid=${lines[4]#uid }
    recorded_gid=${lines[5]#gid }
    recorded_device=${lines[6]#device }
    recorded_inode=${lines[7]#inode }
    recorded_digest=${lines[8]#digest }
    if [[ ${recorded_destination} != "${destination_digest}" \
        || ${recorded_uid} != "${expected_uid}" \
        || ${recorded_gid} != "${expected_gid}" \
        || ! ${staging_name} =~ ^\.executor-master-key\.[A-Za-z0-9]{8}$ \
        || ! ${recorded_uid} =~ ^[0-9]+$ \
        || ! ${recorded_gid} =~ ^[0-9]+$ ]]; then
        executor_installer_error \
            "the master key recovery record does not match this installation"
        return
    fi
    if [[ ${state} == prepared ]]; then
        if [[ ${recorded_device} != - \
            || ${recorded_inode} != - \
            || ${recorded_digest} != - ]]; then
            executor_installer_error "the prepared master key recovery record is malformed"
            return
        fi
    elif [[ ${state} == staged ]]; then
        if [[ ! ${recorded_device} =~ ^[0-9]+$ \
            || ! ${recorded_inode} =~ ^[0-9]+$ \
            || ! ${recorded_digest} =~ ^[0-9a-f]{64}$ ]]; then
            executor_installer_error "the staged master key recovery record is malformed"
            return
        fi
    else
        executor_installer_error "the master key recovery state is unsupported"
        return
    fi

    staging_dir="${staging_parent}/${staging_name}"
    key_tmp="${staging_dir}/master.key"
    if [[ -e ${staging_dir} || -L ${staging_dir} ]]; then
        local directory_metadata directory_type directory_owner directory_mode directory_device
        if ! directory_metadata=$(LC_ALL=C stat \
            --format='%F|%u|%a|%d' -- "${staging_dir}"); then
            executor_installer_error \
                "could not inspect the recorded master key staging directory"
            return
        fi
        IFS='|' read -r directory_type directory_owner directory_mode directory_device \
            <<< "${directory_metadata}"
        if [[ ${directory_type} != directory \
            || ${directory_owner} != "${EUID}" \
            || ${directory_mode} != 700 \
            || ${directory_device} != "${staging_device}" ]]; then
            executor_installer_error \
                "the recorded master key staging directory is unsafe: ${staging_dir}"
            return
        fi
    fi
    [[ -e ${path} || -L ${path} ]] && destination_exists=true
    [[ -e ${key_tmp} || -L ${key_tmp} ]] && alias_exists=true

    if [[ ${state} == prepared ]]; then
        if [[ ${destination_exists} == true ]]; then
            executor_installer_error \
                "a destination key appeared before master key staging completed"
            return
        fi
        if [[ ${alias_exists} == true ]]; then
            executor_validate_prepared_master_key \
                "${key_tmp}" "${staging_device}" \
                "${expected_uid}" "${expected_gid}" || return $?
            if ! rm -f -- "${key_tmp}"; then
                executor_installer_error "could not remove the prepared master key"
                return
            fi
        fi
    elif [[ ${destination_exists} == true ]]; then
        if ! destination_metadata=$(LC_ALL=C stat \
            --format='%d|%i' -- "${path}"); then
            executor_installer_error "could not inspect the recovered master key"
            return
        fi
        IFS='|' read -r destination_device destination_inode \
            <<< "${destination_metadata}"
        if [[ ${destination_device} != "${recorded_device}" \
            || ${destination_inode} != "${recorded_inode}" ]]; then
            executor_installer_error \
                "the destination master key does not match the recovery record"
            return
        fi
        if [[ ${alias_exists} == true ]]; then
            executor_validate_recorded_master_key \
                "${path}" "${recorded_device}" "${recorded_inode}" \
                "${expected_uid}" "${expected_gid}" \
                "${recorded_digest}" 2 || return $?
            executor_validate_recorded_master_key \
                "${key_tmp}" "${recorded_device}" "${recorded_inode}" \
                "${expected_uid}" "${expected_gid}" \
                "${recorded_digest}" 2 || return $?
                if ! rm -f -- "${key_tmp}"; then
                    executor_installer_error \
                        "could not remove the recovered master key alias"
                    return
                fi
        else
            executor_validate_recorded_master_key \
                "${path}" "${recorded_device}" "${recorded_inode}" \
                "${expected_uid}" "${expected_gid}" \
                "${recorded_digest}" 1 || return $?
        fi
    elif [[ ${alias_exists} == true ]]; then
        executor_validate_recorded_master_key \
            "${key_tmp}" "${recorded_device}" "${recorded_inode}" \
            "${expected_uid}" "${expected_gid}" \
            "${recorded_digest}" 1 || return $?
        if ! ln -T -- "${key_tmp}" "${path}"; then
            executor_installer_error \
                "the master key destination appeared during recovery"
            return
        fi
        executor_require_filesystem_sync \
            "${data_dir}" "the recovered published master key" || return $?
        if ! rm -f -- "${key_tmp}"; then
            executor_installer_error "could not remove the recovered master key alias"
            return
        fi
    fi

    if [[ -d ${staging_dir} && ! -L ${staging_dir} ]]; then
        if ! rmdir -- "${staging_dir}"; then
            executor_installer_error \
                "could not remove the recovered master key staging directory"
            return
        fi
    fi
    executor_require_filesystem_sync \
        "${staging_parent}" "the recovered master key staging parent" || return $?
    executor_require_filesystem_sync \
        "${data_dir}" "the recovered master key directory" || return $?
    executor_retire_master_key_recovery "${recovery_path}"
}

executor_require_safe_directory() {
    local path=$1

    if [[ -L ${path} ]]; then
        executor_installer_error "refusing symbolic link at managed directory: ${path}"
        return
    fi
    if [[ -e ${path} && ! -d ${path} ]]; then
        executor_installer_error "managed directory path is not a directory: ${path}"
        return
    fi
}

executor_require_regular_file_or_absent() {
    local path=$1

    if [[ -L ${path} ]]; then
        executor_installer_error "refusing symbolic link at managed path: ${path}"
        return
    fi
    if [[ -e ${path} && ! -f ${path} ]]; then
        executor_installer_error "managed path is not a regular file: ${path}"
        return
    fi
}

executor_validate_master_key_staging_parent() {
    local path=$1
    local metadata file_type owner mode device

    if [[ ! -e ${path} && ! -L ${path} ]]; then
        executor_installer_error "master key staging parent does not exist: ${path}"
        return
    fi
    if ! metadata=$(LC_ALL=C stat \
        --format='%F|%u|%a|%d' -- "${path}"); then
        executor_installer_error \
            "could not inspect master key staging parent: ${path}"
        return
    fi
    IFS='|' read -r file_type owner mode device <<< "${metadata}"

    if [[ ${file_type} != "directory" ]]; then
        executor_installer_error \
            "master key staging parent must be a non-symlinked directory: ${path}"
        return
    fi
    if [[ ${owner} != "${EUID}" ]]; then
        executor_installer_error \
            "master key staging parent must be owned by uid ${EUID}: ${path}"
        return
    fi
    if (((8#${mode} & 0022) != 0)); then
        executor_installer_error \
            "master key staging parent must not be group or other writable: ${path}"
        return
    fi

    printf '%s\n' "${device}"
}

executor_validate_master_key() {
    local path=$1
    local expected_uid=$2
    local expected_gid=$3
    local metadata file_type size links owner group mode

    if [[ ! -e ${path} && ! -L ${path} ]]; then
        executor_installer_error "master key does not exist: ${path}"
        return
    fi

    # GNU stat inspects the directory entry itself unless -L is supplied.
    # Keeping this non-dereferencing prevents validation from following links.
    if ! metadata=$(LC_ALL=C stat \
        --format='%F|%s|%h|%u|%g|%a' -- "${path}"); then
        executor_installer_error "could not inspect master key metadata: ${path}"
        return
    fi
    IFS='|' read -r file_type size links owner group mode <<< "${metadata}"

    if [[ ${file_type} != "regular file" ]]; then
        executor_installer_error "master key must be a regular file: ${path}"
        return
    fi
    if [[ ${size} != 32 ]]; then
        executor_installer_error "${path} must contain exactly 32 bytes"
        return
    fi
    if [[ ${links} != 1 ]]; then
        executor_installer_error "${path} must not have additional hard links"
        return
    fi
    if [[ ${owner} != "${expected_uid}" || ${group} != "${expected_gid}" ]]; then
        executor_installer_error \
            "${path} must already be owned by uid ${expected_uid} and gid ${expected_gid}"
        return
    fi
    if [[ ${mode} != 600 ]]; then
        executor_installer_error "${path} must already have mode 0600"
        return
    fi
}

executor_create_master_key() (
    local staging_parent=$1
    local data_dir=$2
    local path=$3
    local expected_uid=$4
    local expected_gid=$5
    local staging_device data_device validation_status write_status
    local recovery_path destination_digest staging_name key_metadata
    local key_device key_inode key_digest
    local staging_dir=""
    local key_tmp=""

    cleanup_master_key_temp() {
        if [[ -n ${key_tmp} ]]; then
            rm -f -- "${key_tmp}"
        fi
        if [[ -n ${staging_dir} ]]; then
            rmdir -- "${staging_dir}" 2>/dev/null || true
        fi
    }
    trap cleanup_master_key_temp EXIT

    umask 0077
    if ! staging_device=$(executor_validate_master_key_staging_parent \
        "${staging_parent}"); then
        return 1
    fi
    if ! data_device=$(LC_ALL=C stat --format='%d' -- "${data_dir}"); then
        executor_installer_error "could not inspect master key data directory"
        return
    fi
    if [[ ${staging_device} != "${data_device}" ]]; then
        executor_installer_error \
            "master key staging parent and data directory must share a filesystem"
        return
    fi
    if ! staging_dir=$(mktemp -d \
        "${staging_parent}/.executor-master-key.XXXXXXXX"); then
        executor_installer_error "could not create the master key staging directory"
        return
    fi
    if ! chmod 0700 "${staging_dir}"; then
        executor_installer_error "could not secure the master key staging directory"
        return
    fi
    staging_name=${staging_dir##*/}
    key_tmp="${staging_dir}/master.key"
    recovery_path="${staging_parent}/.executor-master-key.recovery"
    if ! destination_digest=$(executor_master_key_path_digest "${path}"); then
        executor_installer_error "could not identify the master key destination"
        return
    fi
    executor_publish_master_key_recovery \
        "${recovery_path}" prepared "${destination_digest}" \
        "${staging_name}" "${expected_uid}" "${expected_gid}" || return $?
    if executor_write_and_sync_master_key "${key_tmp}"; then
        :
    else
        write_status=$?
        executor_installer_error "could not generate the master key"
        return "${write_status}"
    fi
    if ! chown "${expected_uid}:${expected_gid}" "${key_tmp}"; then
        executor_installer_error "could not set temporary master key ownership"
        return
    fi
    if ! chmod 0600 "${key_tmp}"; then
        executor_installer_error "could not set temporary master key permissions"
        return
    fi
    if executor_validate_master_key \
        "${key_tmp}" "${expected_uid}" "${expected_gid}"; then
        :
    else
        validation_status=$?
        return "${validation_status}"
    fi
    executor_require_filesystem_sync \
        "${key_tmp}" "the final master key metadata" || return $?
    if ! key_metadata=$(LC_ALL=C stat --format='%d|%i' -- "${key_tmp}"); then
        executor_installer_error "could not inspect the staged master key identity"
        return
    fi
    IFS='|' read -r key_device key_inode <<< "${key_metadata}"
    if ! key_digest=$(sha256sum -- "${key_tmp}" | awk '{print $1}'); then
        executor_installer_error "could not digest the staged master key"
        return
    fi
    executor_publish_master_key_recovery \
        "${recovery_path}" staged "${destination_digest}" \
        "${staging_name}" "${expected_uid}" "${expected_gid}" \
        "${key_device}" "${key_inode}" "${key_digest}" || return $?
    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_METADATA_SYNC:-} == 1 ]]; then
        kill -KILL "${BASHPID}"
    fi

    # A hard-link publication is atomic and fails if any directory entry has
    # appeared at the destination. The published path is never overwritten.
    if ln -T -- "${key_tmp}" "${path}"; then
        :
    else
        local publication_status=$?
        if ! rm -f -- "${key_tmp}"; then
            executor_installer_error \
                "could not remove the failed master key staging file"
            return
        fi
        key_tmp=""
        if ! rmdir -- "${staging_dir}"; then
            executor_installer_error \
                "could not remove the failed master key staging directory"
            return
        fi
        staging_dir=""
        executor_require_filesystem_sync \
            "${staging_parent}" "the failed master key staging cleanup" || return $?
        executor_retire_master_key_recovery "${recovery_path}" || return $?
        executor_installer_error \
            "master key path appeared during installation; refusing to replace it"
        return "${publication_status}"
    fi
    executor_require_filesystem_sync \
        "${data_dir}" "the published master key directory" || return $?
    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_DESTINATION_SYNC:-} == 1 ]]; then
        kill -KILL "${BASHPID}"
    fi
    if ! rm -f -- "${key_tmp}"; then
        executor_installer_error "could not remove the temporary master key link"
        return
    fi
    key_tmp=""
    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_ALIAS_UNLINK:-} == 1 ]]; then
        kill -KILL "${BASHPID}"
    fi
    if ! rmdir -- "${staging_dir}"; then
        executor_installer_error "could not remove the master key staging directory"
        return
    fi
    staging_dir=""
    executor_require_filesystem_sync \
        "${staging_parent}" "the master key staging parent" || return $?
    executor_require_filesystem_sync \
        "${data_dir}" "the master key directory after publication" || return $?

    executor_validate_master_key "${path}" "${expected_uid}" "${expected_gid}" || return $?
    executor_retire_master_key_recovery "${recovery_path}"
)

executor_ensure_master_key() (
    local staging_parent=$1
    local data_dir=$2
    local path=$3
    local expected_uid=$4
    local expected_gid=$5
    local recovery_path="${staging_parent}/.executor-master-key.recovery"
    local lock_path="${staging_parent}/.executor-master-key.lock"
    local destination_digest staging_device lock_fd lock_metadata fd_identity
    local lock_type lock_owner lock_mode lock_links lock_size lock_device lock_inode

    if ! command -v flock >/dev/null 2>&1; then
        executor_installer_error "flock is required for master key installation"
        return
    fi
    if ! staging_device=$(executor_validate_master_key_staging_parent \
        "${staging_parent}"); then
        return 1
    fi
    umask 0077
    if [[ ! -e ${lock_path} && ! -L ${lock_path} ]]; then
        if ! (set -o noclobber; : > "${lock_path}") 2>/dev/null \
            && [[ ! -e ${lock_path} || -L ${lock_path} ]]; then
            executor_installer_error "could not create the master key installation lock"
            return
        fi
    fi
    if ! lock_metadata=$(LC_ALL=C stat \
        --format='%F|%u|%a|%h|%s|%d|%i' -- "${lock_path}"); then
        executor_installer_error "could not inspect the master key installation lock"
        return
    fi
    IFS='|' read -r lock_type lock_owner lock_mode lock_links lock_size \
        lock_device lock_inode <<< "${lock_metadata}"
    if [[ ${lock_type} != "regular empty file" \
        || ${lock_owner} != "${EUID}" \
        || ${lock_mode} != 600 \
        || ${lock_links} != 1 \
        || ${lock_size} != 0 \
        || ${lock_device} != "${staging_device}" ]]; then
        executor_installer_error \
            "the master key installation lock has unsafe metadata"
        return
    fi
    if ! exec {lock_fd}<>"${lock_path}"; then
        executor_installer_error "could not open the master key installation lock"
        return
    fi
    if ! fd_identity=$(LC_ALL=C stat -L \
        --format='%d|%i' -- "/proc/self/fd/${lock_fd}") \
        || [[ ${fd_identity} != "${lock_device}|${lock_inode}" ]]; then
        executor_installer_error "the master key installation lock changed while opening"
        return
    fi
    executor_require_filesystem_sync \
        "${lock_path}" "the master key installation lock" || return $?
    executor_require_filesystem_sync \
        "${staging_parent}" "the master key lock directory" || return $?
    if ! flock -n -x "${lock_fd}"; then
        executor_installer_error "another master key installation is already active"
        return
    fi
    if ! destination_digest=$(executor_master_key_path_digest "${path}"); then
        executor_installer_error "could not identify the master key destination"
        return
    fi
    executor_recover_master_key \
        "${staging_parent}" "${data_dir}" "${path}" \
        "${expected_uid}" "${expected_gid}" "${recovery_path}" \
        "${destination_digest}" "${staging_device}" || return $?

    if [[ -e ${path} || -L ${path} ]]; then
        executor_validate_master_key \
            "${path}" "${expected_uid}" "${expected_gid}" || return $?
        executor_require_filesystem_sync \
            "${data_dir}" "the existing master key directory" || return $?
        return 0
    fi

    executor_create_master_key \
        "${staging_parent}" "${data_dir}" "${path}" \
        "${expected_uid}" "${expected_gid}"
)
