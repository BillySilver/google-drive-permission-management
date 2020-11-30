from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools

import sys
from enum import Enum
from collections import namedtuple
from googleapiclient.http import BatchHttpRequest


def google_pager(req_obj, iter_resp_field, next_page_func):
    """Iterates through a Google Drive paged response.

    :param req_obj: The initial object to start the paging.
    :param iter_resp_field: The field of the response to turn into a list
    :param next_page_func: The function to call to get the next page.
    :return: Objects from the response's list field.
    """
    while req_obj is not None:
        results = req_obj.execute()

        drive_objs = results.get(iter_resp_field, [])

        for drive_obj in drive_objs:
            yield drive_obj

        req_obj = next_page_func(req_obj, results)


class RenameGoogleObject(object):
    """Renames a given Google Drive object temporarily to prevent naming issues."""
    def __init__(self, drive_obj, api_object):
        self._drive_obj = drive_obj
        self._service = api_object

    def __enter__(self):
        # Rename drive object
        self._service.files().update(fileId=self._drive_obj["id"],
                                     body={"name": "Old - " + self._drive_obj["name"]}).execute()
        return self._drive_obj

    def __exit__(self, type, value, traceback):
        # Undo drive object renaming
        self._service.files().update(fileId=self._drive_obj["id"],
                                     body={"name": self._drive_obj["name"]}).execute()


class MIMEType(Enum):
    GOOGLE_OBJECT = "application/vnd.google-apps."
    FOLDER = "application/vnd.google-apps.folder"


class CollaboratorType(Enum):
    READER = "reader",
    WRITER = "writer",
    COMMENTER = "commenter"


class EnhancedBatchHttpRequest(BatchHttpRequest):
    """Google batch request object that automatically calls execute on itself when too many calls are batched."""
    CAP = 100

    def __init__(self, service, **kwargs):
        if "batch_uri" not in kwargs:
            kwargs["batch_uri"] = service.new_batch_http_request()._batch_uri
        super(EnhancedBatchHttpRequest, self).__init__(**kwargs)
        self._counter = 0
        self._kwargs = kwargs

        # Hidden batch for modtime.
        self._modtime_batch = BatchHttpRequest(**kwargs)

    def add(self, *args, **kwargs):
        super(EnhancedBatchHttpRequest, self).add(*args, **kwargs)
        self._counter += 1

        if self._counter >= self.CAP:
            self.execute()

    def clear(self):
        super(EnhancedBatchHttpRequest, self).__init__(**self._kwargs)
        self._counter = 0
        self._modtime_batch.__init__(**self._kwargs)

    def execute(self, *args, **kwargs):
        super(EnhancedBatchHttpRequest, self).execute(*args, **kwargs)
        self._modtime_batch.execute(*args, **kwargs)
        self.clear()

    def add_modtime(self, *args, **kwargs):
        self._modtime_batch.add(*args, **kwargs)

class GoogleDriveOperations(object):
    SCOPES = "https://www.googleapis.com/auth/drive"
    STD_FIELDS = "name,id,parents,owners,modifiedTime,kind,mimeType"
    _STD_FIELDS = "name,id,parents,owners,modifiedTime,kind,mimeType"
    STD_FIELDS_LIST = "files({0})".format(STD_FIELDS)
    _STD_FIELDS_LIST = "files({0})".format(STD_FIELDS)

    def __init__(self, folder, td_id=None, retry=False):
        self._service = self._setup()
        self._td_id = td_id
        self._is_teamdrive = (td_id is not None)
        # Setup publicly-available variables (early setup for retry).
        self.service = self._service
        self.td_id = td_id
        self.is_teamdrive = self._is_teamdrive
        if retry is True:
            return
        temp_user_info = self._service.about().get(fields="user(emailAddress, permissionId)").execute().get("user")
        self._userinfo = namedtuple("UserInfo", temp_user_info.keys())(*temp_user_info.values())
        self._subfolder_ids = self.enumerate_subfolder_ids(folder)

        # Setup publicly-available variables
        self.subfolder_ids = self._subfolder_ids
        self.userinfo = self._userinfo

    def _setup(self):
        """Handles initializing the Google Drive API authentication.

        :return: Authenticated Google Drive API service object
        """
        # Setup the Drive v3 API
        store = file.Storage("token.json")
        creds = store.get()
        if not creds or creds.invalid:
            flow = client.flow_from_clientsecrets("client_id.json", self.SCOPES)
            creds = tools.run_flow(flow, store)
        return build("drive", "v3", http=creds.authorize(Http()))

    def get_permissions(self, file_resource):
        """Get all permissions for a file.

        :param file_resource: The file to query permissions for.
        :return: All permissions on the file.
        """
        permissions = []

        perm_request = self._service.permissions().list(fileId=file_resource["id"],
                                                        fields="permissions(id,type,emailAddress,role)",
                                                        supportsAllDrives=self._is_teamdrive)

        for permission in google_pager(perm_request, "permissions", self._service.permissions().list_next):
            permissions.append(permission)

        return permissions

    def get_owner_email(self, file_resource):
        """Get the email of the file owner.

        :param file_resource: The file to get the owner's email for.
        :return: The owner's email
        """
        perms = self.get_permissions(file_resource)     # Ignore batching in here, should only be a special case
        for perm in perms:
            if perm["role"] == "owner":
                return perm["emailAddress"]

        raise ValueError("Cannot find owner email address for '{0}'.".format(file_resource["name"]))

    def is_owner(self, file_resource):
        """Checks if the current user owns the file.

        :param file_resource: The file to check the owner of.
        :return: True if current user owns the file
        """
        # Get permissions if not in original request
        if "owners" not in file_resource:
            owners = self._service.files().get(fileId=file_resource["id"],
                                               fields=self._STD_FIELDS).execute().get("owners", [])
            # Ignore batching in here, can be dealt with in caller's side
        else:
            owners = file_resource.get("owners", [])

        for owner in owners:
            if owner["permissionId"] == self._userinfo.permissionId:
                return True
        return False

    def add_permission(self, file_resource, email, keep_modtime, what_if, role=CollaboratorType.WRITER, batch=None):
        """Given a file and and a collaborator email, adds them.

        :param file_resource: The file containing the permission
        :param email: The email of the collaborator to add
        :param keep_modtime: Should the modified time of the file be reserved?
        :param what_if: If the function shouldn't actually run and instead print out what it was going to do.
        :param role: The permission that the collaborator will be allowed to take. Defaults to Writer.
        :param batch: Object to add the addition to. Otherwise execute addition immediately.
        :return: None
        """
        file_name = file_resource["name"]

        # Setup action message
        msg = "{2}Adding access to '{0}' for '{1}'.".format(file_name,
                                                            email,
                                                            "What-If: " if what_if else "")
        print(msg)

        # Stop here if what-if is requested
        if what_if:
            return

        command = self._service.permissions().create(fileId=file_resource["id"],
                                                     body={'emailAddress': email, 'role': role.value})

        if batch is None:
            command.execute()
        else:
            batch.add(command)

        if keep_modtime:
            self._restore_modtime(file_resource["id"], file_resource["modifiedTime"], batch)

    def delete_permission(self, file_resource, perm, keep_modtime, what_if, batch=None):
        """Given a file and and a permission, deletes it.

        :param file_resource: The file containing the permission
        :param perm: The permission to delete
        :param keep_modtime: Should the modified time of the file be reserved?
        :param what_if: If the function shouldn't actually run and instead print out what it was going to do.
        :param batch: Object to add the deletion to. Otherwise execute deletion immediately.
        :return: None
        """
        shared_link = (perm["type"] in ["anyone", "domain"])
        file_name = file_resource["name"]

        # Setup action message
        if shared_link:
            msg = "{1}Disabling link for '{0}'".format(file_name, "What-If: " if what_if else "")
        else:
            msg = "{2}Deleting access to '{0}' for '{1}'.".format(file_name,
                                                                  perm["emailAddress"],
                                                                  "What-If: " if what_if else "")
        print(msg)

        # Stop here if what-if is requested
        if what_if:
            return

        command = self._service.permissions().delete(fileId=file_resource["id"], permissionId=perm["id"],
                                                     supportsAllDrives=self._is_teamdrive)

        if batch is None:
            command.execute()
        else:
            batch.add(command)

        if keep_modtime:
            self._restore_modtime(file_resource["id"], file_resource["modifiedTime"], batch)

    def _restore_modtime(self, fileId, modifiedTime, batch=None):
        command = self._service.files().update(fileId=fileId,
                                               supportsAllDrives=self._is_teamdrive,
                                               body={"modifiedTime": modifiedTime})

        if batch is None:
            command.execute()
        else:
            batch.add_modtime(command)

    @staticmethod
    def _default_batch_callback(rid, resp, err):
        if err is not None:
            print(err, file=sys.stderr)

    def _take_ownership_folder(self, drive_obj, parents):
        """Take ownership of a folder by making a new folder and moving it's contents.

        :param drive_obj: The folder to take ownership of
        :param parents: The parents of this folder that are within the scope of the top-level folder.
        :return: The new drive object representing the new folder.
        """
        # Rename old folder to prevent naming conflicts
        with RenameGoogleObject(drive_obj, self._service):
            # Create new folder
            new_folder_results = self._service.files().create(body={"parents": parents,
                                                                    "name": drive_obj["name"],
                                                                    "mimeType": MIMEType.FOLDER.value
                                                                    }).execute()
            new_folder_meta = self._service.files().get(fileId=new_folder_results["id"],
                                                        fields=self._STD_FIELDS).execute()

            # Batch the movement of files and folder deletion
            move_batch = EnhancedBatchHttpRequest(self._service, callback=self._default_batch_callback)

            # Move all child files/folders to new folder
            obj_request = self._service.files().list(pageSize=1000,
                                                     q="'{0}' in parents".format(drive_obj["id"]),
                                                     fields="nextPageToken," + self._STD_FIELDS_LIST)

            for sub_obj in google_pager(obj_request, "files", self._service.files().list_next):
                move_batch.add(self._service.files().update(fileId=sub_obj["id"],
                                                            addParents=new_folder_meta["id"],
                                                            removeParents=drive_obj["id"]))

            move_batch.execute()

            # Remove the old object from the folder tree
            self._service.files().update(fileId=drive_obj["id"],
                                         removeParents=",".join(parents)).execute()

            return new_folder_meta

    def take_ownership(self, drive_obj, what_if):
        """Takes ownership of an object by creating a copy and removing the original from the folder.

        :param drive_obj: The object to take ownership of.
        :param what_if: If the function shouldn't actually run and instead print out what it was going to do.
        :return: a new drive object representing the new object.
        """
        msg = "{1}Taking ownership of object '{0}'".format(drive_obj["name"], "What-If: " if what_if else "")
        print(msg)

        # Stop here if only What-If is requested
        if what_if:
            return

        # Check if file is already owned by user
        if self.is_owner(drive_obj):
            print("'{0}' is already owned by '{1}'.".format(drive_obj["name"], self._userinfo.emailAddress))
            return drive_obj

        # Determine parents to remove from original file
        parents = set(drive_obj["parents"])
        par_to_remove = [item for item in parents.intersection(self._subfolder_ids)]

        # If folder, use folder take ownership process
        if drive_obj["mimeType"] == MIMEType.FOLDER.value:
            return self._take_ownership_folder(drive_obj, par_to_remove)

        # Rename old object to prevent naming conflicts
        with RenameGoogleObject(drive_obj, self._service):
            # Copy object to same places
            new_obj_results = self._service.files().copy(fileId=drive_obj["id"],
                                                         body={"parents": par_to_remove,
                                                               "name": drive_obj["name"]
                                                               }).execute()
            new_obj_meta = self._service.files().get(fileId=new_obj_results["id"], fields=self._STD_FIELDS).execute()

            # Remove the old object from the folder tree
            self._service.files().update(fileId=drive_obj["id"], removeParents=",".join(par_to_remove)).execute()

            return new_obj_meta

    def enumerate_subfolder_ids(self, folder):
        """Given a top-level folder name, gets folder ID and IDs of all subfolders

        :param folder: The name of the folder to enumerate.
        :return: Subfolder IDs (set), string for filtering Google Drive results to folder or subfolders.
        """
        print("Scanning folders...")
        from time import time
        sec_bgn = time()

        # Find the ID of the top-level folder, and then collect all subfolder IDs
        try:
            if not self._is_teamdrive:
                top_id = self._service.files().list(pageSize=1,
                                                    q="mimeType = 'application/vnd.google-apps.folder' "
                                                      "and name = '{0}'".format(folder),
                                                    fields="nextPageToken," + self._STD_FIELDS_LIST)\
                    .execute()["files"][0]["id"]
            else:
                top_id = self._service.files().list(pageSize=1,
                                                    q="mimeType = 'application/vnd.google-apps.folder' "
                                                      "and name = '{0}'".format(folder),
                                                    supportsAllDrives=True,
                                                    includeItemsFromAllDrives=True,
                                                    corpora="drive",
                                                    driveId=self._td_id,
                                                    fields="nextPageToken," + self._STD_FIELDS_LIST)\
                    .execute()["files"][0]["id"]
        except IndexError:
            # This could error out with bad name
            raise FileNotFoundError("Folder '{0}' was not found.".format(folder))

        folder_ids_set = self._collect_all_subfolders(top_id)
        folder_ids_set.add(top_id)

        print("Finished scanning folders in %d seconds." % (time()-sec_bgn))
        return folder_ids_set

    def _collect_all_subfolders(self, top_folder_id):
        """Gathers all the IDs of the subfolders in a specified top-level folder.

        :param top_folder_id: The top-level folder to get subfolders of
        :return: set of ids of all subfolders (excluding top-level folder ID)
        """
        subfolder_ids = set()

        if not self._is_teamdrive:
            folder_request = self._service.files().list(pageSize=1000, q="mimeType = 'application/vnd.google-apps.folder'"
                                                                         " and '{0}' in parents".format(top_folder_id),
                                                        fields="nextPageToken,files(name,id,parents)")
        else:
            folder_request = self._service.files().list(pageSize=1000, q="mimeType = 'application/vnd.google-apps.folder'"
                                                                         " and '{0}' in parents".format(top_folder_id),
                                                        supportsAllDrives=True,
                                                        includeItemsFromAllDrives=True,
                                                        corpora="drive",
                                                        driveId=self._td_id,
                                                        fields="nextPageToken,files(name,id,parents)")

        for drive_folder in google_pager(folder_request, "files", self._service.files().list_next):
            subfolder_ids.update(self._collect_all_subfolders(drive_folder["id"]))
            subfolder_ids.add(drive_folder["id"])

        return subfolder_ids
