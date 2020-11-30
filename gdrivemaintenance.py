#! /usr/bin/env python3

import sys
import argparse
import re, json
from GoogleDriveOperations import GoogleDriveOperations, google_pager, EnhancedBatchHttpRequest
import googleapiclient.errors


def version_extraction():
    """Provides the version number of the program from the VERSION file.

    :return: Version number as a string
    """
    with open("VERSION", "r") as vers:
        return vers.read()


def argument_parsing():
    """Parses command line arguments, and provides help text, if desired.

    :return: Parsed arguments
    """
    version = version_extraction()
    parser = argparse.ArgumentParser(description="Update sharing and ownership permissions on Google Drive"
                                                 " files/folders to match a predefined list.")
    parser.add_argument("folder", type=str, nargs="?", default="WE Bots",
                        help="The folder to recursively start changing sharing and ownership.")
    parser.add_argument("--collaborators", "-c", metavar="email", type=str, nargs="+", action="append", default=[],
                        help="the collaborators that should exist on the files/folders."
                             " If blank, removes all collaborators.")
    parser.add_argument("--take-ownership", "-t", action="store_true", default=False,
                        help="should files/folders have their ownership changed")
    parser.add_argument("--disable-links", "-l", action="store_true", default=False,
                        help="Disable all sharing by links")
    parser.add_argument("--what-if", "-n", action="store_true", default=False,
                        help="shows what would happen, without actually executing changes to Google Drive")
    parser.add_argument("--version", "-v", action="version", version="%(prog)s {0}".format(version))
    parser.add_argument("--teamdrive", "-td", metavar="teamdrive_id", type=str, default=None,
                        help="Team Drive ID (disable-links only).")
    parser.add_argument("--files-only", action="store_true", default=False,
                        help="ignore any folders, only check and update permissions on files.")
    parser.add_argument("--retry", metavar="log_filename", type=str,
                        help="continue via a \"perm_edit_err.log\" file. you should rename it first"
                             " since it might be overwritten.")
    parser.add_argument("--keep-modtime", action="store_true", default=False,
                        help="keep modified time. it's useful for sync tools.")

    args = parser.parse_args()

    # Flatten collaborators and convert to set
    args.collaborators = set([item for sublist in args.collaborators for item in sublist])

    if args.teamdrive is not None:
        if len(args.collaborators) > 0 or args.take_ownership:
            raise "It only supports disable-links on a team drive."

    if args.retry == "perm_edit_err.log":
        raise "Filename of log \"perm_edit_err.log\" is not allowed. Please rename it first."

    return args


def perm_edit_err_logger(exception):
    err_log = json.loads(exception.content)["error"]
    if err_log["code"] == 404 and err_log["message"].find("Permission not found") >= 0:
        # Tried to delete a non-existed permission (most likely has be deleted).
        return

    m = re.search(perm_edit_err_logger.re_uri_perm, exception.uri)
    if m is None:
        return

    fileId = m.group(1)
    permissionId = m.group(2)
    with open("perm_edit_err.log", "a") as f:
        if permissionId is not None:
            print("del %s %s" % (fileId, permissionId[1: ]), file=f)
        else:
            print("add %s" % (fileId), file=f)

perm_edit_err_logger.re_uri_perm = \
    r"https://www.googleapis.com/drive/v3/files/([^/]+)/permissions(/\d+|/anyoneWithLink)?"


def perm_edit_callback(id, response, exception):
    if exception is not None:
        print("Batch execution callback failed:", file=sys.stderr)
        print(exception, file=sys.stderr)
        perm_edit_err_logger(exception)


def retry_from_log(api_client, perm_edit_err_log, keep_modtime, what_if):
    lines = []
    with open(perm_edit_err_log, "r") as f:
        for line in f:
            lines.append(line)

    # Batch all the permission changes, since they don't have dependencies
    batch = EnhancedBatchHttpRequest(api_client.service, callback=perm_edit_callback)

    n_cmd_batch = 100
    for cnt in range(len(lines)):
        if cnt % n_cmd_batch == 0:
            # Show progress.
            print("** %d-%d of %d commands **" % (cnt+1, min(cnt+n_cmd_batch, len(lines)), len(lines)))

        line = lines[cnt].split()
        cmd, fileId = line[ :2]
        if cmd == "add":
            raise "retrying for add permissions is currently not supported."
            # command = api_client.service.permissions().create(fileId=fileId,
            #                                                   body={'emailAddress': email, 'role': role.value})
        elif cmd == "del":
            permissionId = line[2]

            # Setup action message
            if permissionId == "anyoneWithLink":
                msg = "{1}Disabling link for fileId: '{0}'".format(fileId, "What-If: " if what_if else "")
            else:
                # An organization has its own permissionId, that is, it is regarded as a regular user.
                msg = "{2}Deleting access to fileId: '{0}' for permissionId: '{1}'.".format(
                    fileId, permissionId, "What-If: " if what_if else "")
            print(msg)

            # Stop here if what-if is requested
            if what_if:
                continue

            command = api_client.service.permissions().delete(fileId=fileId, permissionId=permissionId,
                                                              supportsAllDrives=api_client.is_teamdrive)
            batch.add(command)
        else:
            raise "perm_edit_err_log error: unknown format."

    batch.execute()


def td_disable_links(api_client, file_resource, keep_modtime, what_if, permissions=None, batch=None):
    if permissions is None:
        permissions = api_client.get_permissions(file_resource)
    for perm in permissions:
        if perm["type"] in ["anyone", "domain"]:
            api_client.delete_permission(file_resource,
                                         perm,
                                         keep_modtime,
                                         what_if,
                                         batch)


def modify_permissions(api_client, file_resource, collaborators, disable_links, keep_modtime, what_if,
                       permissions=None, batch=None):
    """Edits permissions on a file owned by the executor to match the 'collaborators' preference.

    :param api_client: The Google API object wrapper to interact with
    :param file_resource: The file to modify permissions for.
    :param collaborators: Collaborators allowed on the file.
    :param disable_links: Should a shared link be disabled?
    :param keep_modtime: Should the modified time of the file be reserved?
    :param what_if: Should permission modification happen, or just print what would happen?
    :param permissions: The file's permissions. Will be retrieved fresh if blank.
    :param batch: Object to use for batching permission edits, if provided.
    :return: None
    """
    if api_client.is_teamdrive:
        # Check that link disabling is requested
        if not disable_links:
            return
        return td_disable_links(api_client, file_resource, keep_modtime, what_if, permissions, batch)

    batch_internal = api_client.service.new_batch_http_request(perm_edit_callback)  # Batch at the file level or higher

    # If permissions aren't already supplied, retrieve them
    if permissions is None:
        permissions = api_client.get_permissions(file_resource)

    # Delete unwanted permissions as specified by the requested state
    for perm in permissions:
        if perm["type"] in ["anyone", "domain"]:
            # Check that link disabling is requested
            if not disable_links:
                continue

            api_client.delete_permission(file_resource,
                                         perm,
                                         keep_modtime,
                                         what_if,
                                         batch if batch is not None else batch_internal)
        elif perm["emailAddress"] not in collaborators:
            api_client.delete_permission(file_resource,
                                         perm,
                                         keep_modtime,
                                         what_if,
                                         batch if batch is not None else batch_internal)

    # Add wanted permissions as specified by requested state
    wanted_collaborators = collaborators
    existing_collaborators = set([perm["emailAddress"] for perm in permissions if "emailAddress" in perm])
    missing_collaborators = wanted_collaborators - existing_collaborators

    for collab_email in missing_collaborators:
        api_client.add_permission(file_resource,
                                  collab_email,
                                  keep_modtime,
                                  what_if,
                                  batch=batch if batch is not None else batch_internal)

    if batch is None:
        batch_internal.execute()     # Bulk-delete sharing edits on this file if not batching at a higher level


def main():

    # Step 1: Get all files and folders
    # Step 2: Copy objects that don't belong to executor, move sub-objects if needed, and delete old objects
    # Step 3: Restrict sharing

    args = argument_parsing()
    try:
        ops = GoogleDriveOperations(args.folder,
                                    td_id=args.teamdrive,
                                    retry=args.retry is not None)
    except FileNotFoundError:
        print("Folder '{0}' not found. Exiting...".format(args.folder), file=sys.stderr)
        sys.exit(1)

    if args.retry is not None:
        return retry_from_log(ops, args.retry, args.keep_modtime, args.what_if)

    # Add current user to collaborators if not present
    if ops.userinfo.emailAddress not in args.collaborators:
        args.collaborators.add(ops.userinfo.emailAddress)

    # Call the Drive v3 API to get all files for processing
    print("Fixing owners and sharing permissions in files and folders...")

    # Batch all the permission changes, since they don't have dependencies
    perm_batch = EnhancedBatchHttpRequest(ops.service, callback=perm_edit_callback)

    subfolder_ids = list(ops.subfolder_ids)
    n_folder_batch = 10
    for i in range(0, len(subfolder_ids), n_folder_batch):
        # Send a request for every 'n_folder_batch' folders.
        subfolder_ids_batch = subfolder_ids[i:i+n_folder_batch]
        subfolder_filter = "mimeType != 'application/vnd.google-apps.folder' and " if args.files_only else ""
        if len(subfolder_ids) > 1:
            subfolder_filter += "('" + "' in parents or '".join(subfolder_ids_batch) + "' in parents)"
        else:
            subfolder_filter = "('%s' in parents)" % subfolder_ids_batch[0]

        # Show progress.
        print("** %d-%d of %d folders **" % (i+1, i+len(subfolder_ids_batch), len(subfolder_ids)))

        if not ops.is_teamdrive:
            file_request = ops.service.files().list(pageSize=1000, q=subfolder_filter,
                                                    fields="nextPageToken," + GoogleDriveOperations.STD_FIELDS_LIST)
        else:
            file_request = ops.service.files().list(pageSize=1000, q=subfolder_filter,
                                                    supportsAllDrives=True,
                                                    includeItemsFromAllDrives=True,
                                                    corpora="drive",
                                                    driveId=ops.td_id,
                                                    fields="nextPageToken," + GoogleDriveOperations.STD_FIELDS_LIST)

        for drive_obj in google_pager(file_request, "files", ops.service.files().list_next):
            # Fix ownership if desired, then fix permissions
            try:
                if args.take_ownership and not ops.is_owner(drive_obj):
                    drive_obj = ops.take_ownership(drive_obj, args.what_if)

                if drive_obj is not None:   # None is possible when "What-If" is requested

                    # If the ownership changes are not requested, add the owner to the allowed collaborators list
                    if not ops.is_teamdrive:
                        aug_collaborators = set(args.collaborators)
                        if not args.take_ownership:
                            aug_collaborators.add(ops.get_owner_email(drive_obj))
                    else:
                        aug_collaborators = set()

                    modify_permissions(ops,
                                       drive_obj,
                                       aug_collaborators,
                                       args.disable_links,
                                       args.keep_modtime,
                                       args.what_if,
                                       batch=perm_batch)
            except googleapiclient.errors.HttpError as err:
                print("Error modifying state for '{0}', skipping...".format(drive_obj["name"]), file=sys.stderr)
                print(err, file=sys.stderr)

    # Execute all permission changes
    perm_batch.execute()


if __name__ == "__main__":
    main()
