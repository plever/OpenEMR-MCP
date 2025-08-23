import requests

# Default to the open EMR demo apis
OPENEMR_URL = "https://demo.openemr.io/openemr/apis/default"
REGISTRATION_ENDPOINT = f"{OPENEMR_URL}/oauth2/default/registration"
TOKEN_ENDPOINT = f"{OPENEMR_URL}/oauth2/default/token"
    

def register_test_client(redirect_uris:list, post_logout_redirect_uris:list, scope:str, client_name:str="simple-test-client") -> tuple:
    """ Register a new OAuth2 test client with OpenEMR.  
    
    ###################################################################
    #### Not to be used in production. Just for testing/debugging #####
    ###################################################################

    See https://github.com/openemr/openemr/blob/rel-702/API_README.md#authorization for more details.

    Note: After you've refistered a client you'll need to enable the client toekn in OpenEMR UI under 
          Admin -> System -> Api Clients (Based on openemr 7.0.2 UI)
    
    :param redirect_uris: List of redirect URIs for the client.
    :param post_logout_redirect_uris: List of post-logout redirect URIs.
    :param scope: The scope of access requested by the client.
    
    :return: Tuple containing the client ID and client secret.
    """
        
    registration_payload = {
        "application_type": "private",
        "redirect_uris": redirect_uris,
        "post_logout_redirect_uris": post_logout_redirect_uris,
        "initiate_login_uri": "",
        "client_name": "simple-test-client",  #TODO make this configurable
        "token_endpoint_auth_method": "client_secret_post",
        "scope": scope
    }

    resp = requests.post(REGISTRATION_ENDPOINT, json=registration_payload, verify=False)
    resp.raise_for_status()
    reg_data = resp.json()

    client_id = reg_data.get("client_id")
    client_secret = reg_data.get("client_secret")
    
    return client_id, client_secret

#TODO support other grant types...
def password_grant_oauth_token(client_id:str, scope:str, username:str="admin", password:str="pass", 
                               token_endpoint:str=TOKEN_ENDPOINT, user_role:str="users") -> str:
    """ Get an OAuth2 access token using the password grant type.
    
     See https://github.com/openemr/openemr/blob/rel-702/API_README.md#authorization for more details.

    :param client_id: The client ID of the registered application.
    :param scope: The scope of access requested.
    :param username: The username of the user to authenticate (default is "admin").
    :param password: The password of the user to authenticate (default is "pass").
    :param token_endpoint: The endpoint to request the token from (default is TOKEN_ENDPOINT).  
    
    :return: The access token as a string.
    """

    
    token_payload = {
        "grant_type": "password",
        "client_id": client_id,
        "scope": scope,
        "user_role": user_role,
        "username": username,
        "password": password
    }

    resp = requests.post(token_endpoint, data=token_payload, verify=False)
    resp.raise_for_status()
    token_data = resp.json()

    access_token = token_data.get("access_token")

    return access_token


class OpenEMRClient:
    
    def __init__(self, base_url: str, token: str = None):
        """
        
        base_url: The base URL of the OpenEMR API (e.x.. "https://demo.openemr.io/openemr/apis/default")
        token: Bearer token for authentication (optional at init, can be set later)
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if token:
            self.set_token(token)

    def set_token(self, token: str) -> None:
        """Set or update the OAuth2 Bearer token.
        
        :param token: The Bearer token to use for authentication.

        """
        self.session.headers.update({'Authorization': f'Bearer {token}'})

    def _request(self, method: str, path: str, **kwargs):
        """Internal helper for making HTTP requests.
        
        :param method: HTTP method (GET, POST, PUT, DELETE, etc.)
        :param path: API endpoint path (e.g., "/api/facility")
        :param kwargs: Additional parameters for the request (e.g., json, params, data, etc.)   

        """
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, **kwargs)
        resp.raise_for_status()

        # TODO handle redirects and continues

        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -------------------------------
    # fhir/Allergy 
    # -------------------------------
    def list_allergey_intolerance(self, **filters) -> dict:
        """List allergy/intolerance records with optional filters.
        
        :param filters: Optional query parameters to filter the list.
        
        :return: Dict JSON response containing the list of allergy/intolerance records.
        """
        return self._request("GET", "/fhir/AllergyIntolerance", params=filters)
    
    def get_allergy_intolerance(self, auuid: str) -> dict:
        """Get details of a specific allergy/intolerance by UUID.
        
        :param auuid: The UUID of the allergy/intolerance to retrieve.
        
        :return: Dict JSON response containing the allergy/intolerance details.
        """
        if not auuid:
            raise ValueError("Allergy/Intolerance UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/AllergyIntolerance/{auuid}")
    
    # -------------------------------
    # fhir/Appointment 
    # -------------------------------    
    def list_appointments(self, **filters) -> dict:
        """List appointments with optional filters.
        
        :param filters: Optional query parameters to filter the appointment list.
        
        :return: Dict JSON response containing the list of appointments.
        """
        return self._request("GET", "/fhir/Appointment", params=filters)


    def get_appointment(self, auuid: str) -> dict:
        """Get details of a specific appointment by UUID.
        
        :param auuid: The UUID of the appointment to retrieve.
        
        :return: Dict JSON response containing the appointment details.
        """
        if not auuid:
            raise ValueError("Appointment UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Appointment/{auuid}")

    # -------------------------------
    # fhir/Care  
    # -------------------------------  
    def list_care_plans(self, **filters) -> dict:
        """List care plans with optional filters.
        
        :param filters: Optional query parameters to filter the care plan list.
        
        :return: Dict JSON response containing the list of care plans.
        """
        
        return self._request("GET", "/fhir/CarePlan", params=filters)

    def get_care_plan(self, cuid: str) -> dict:
        """Get details of a specific care plan by UUID.
        
        :param cuid: The UUID of the care plan to retrieve.
        
        :return: Dict JSON response containing the care plan details.
        """
        if not cuid:
            raise ValueError("Care Plan UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/CarePlan/{cuid}")

    def list_care_team(self, **filters) -> dict:
        """Get details of a specific care team by UUID.
        
        :param filters: Optional query parameters to filter the care team list.

        :return: Dict JSON response containing the care team details.
        """
        
        return self._request("GET", f"/fhir/CareTeam", params=filters)

    def get_care_team_by_uuid(self, cuid: str) -> dict:
        """Get details of a specific care team by UUID.
        
        :param cuid: The UUID of the care team to retrieve.
        
        :return: Dict JSON response containing the care team details.
        """
        if not cuid:
            raise ValueError("Care Team UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/CareTeam/{cuid}")
    
    def list_conditions(self, **filters) -> dict:
        """List conditions that the user has access to.
        
        :return: Dict JSON response containing the list of conditions.
        """
        
        return self._request("GET", f"/fhir/Condition", params=filters)

    # -------------------------------
    # fhir/Coverage
    # -------------------------------
    def list_coverages(self, **filters) -> dict:
        """List coverages with optional filters.
        
        :param filters: Optional query parameters to filter the coverage list.
        
        :return: Dict JSON response containing the list of coverages.
        """
        
        return self._request("GET", "/fhir/Coverage", params=filters)
    
    def get_coverage(self, cuid: str) -> dict:
        """Get details of a specific coverage by UUID.
        
        :param cuid: The UUID of the coverage to retrieve.
        
        :return: Dict JSON response containing the coverage details.
        """
        if not cuid:
            raise ValueError("Coverage UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Coverage/{cuid}")
    
    # -------------------------------
    # fhir/Device
    # -------------------------------  
    def list_devices(self, **filters) -> dict:
        """List devices with optional filters.
        
        :param filters: Optional query parameters to filter the device list.
        
        :return: Dict JSON response containing the list of devices.
        """
        
        return self._request("GET", "/fhir/Device", params=filters)
    
    def get_device(self, duuid: str) -> dict:
        """Get details of a specific device by UUID.
        
        :param duuid: The UUID of the device to retrieve.
        
        :return: Dict JSON response containing the device details.
        """
        if not duuid:
            raise ValueError("Device UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Device/{duuid}")

    # -------------------------------
    # fhir/DiagnosticReport
    # -------------------------------
    def list_diagnostic_reports(self, **filters) -> dict:
        """List diagnostic reports with optional filters.
        
        :param filters: Optional query parameters to filter the diagnostic report list.
        
        :return: Dict JSON response containing the list of diagnostic reports.
        """
        
        return self._request("GET", "/fhir/DiagnosticReport", params=filters)

    def get_diagnostic_report(self, duuid: str) -> dict:
        """Get details of a specific diagnostic report by UUID.
        
        :param duuid: The UUID of the diagnostic report to retrieve.
        
        :return: Dict JSON response containing the diagnostic report details.
        """
        if not duuid:
            raise ValueError("Diagnostic Report UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/DiagnosticReport/{duuid}")

    def list_facilities(self, **filters) -> dict:
        """List facilities with optional filters.
        
        :param filters: Optional query parameters to filter the facility list.
        
        :return: Dict JSON response containing the list of facilities.
        """

        return self._request("GET", "/fhir/Facility", params=filters)
    
    # -------------------------------
    # fhir/DocumentReference
    # -------------------------------  
    def list_document_reference(self, **filters) -> dict:
        """List document references with optional filters.
        
        :param filters: Optional query parameters to filter the document reference list.
        
        :return: Dict JSON response containing the list of document references.
        """

        return self._request("GET", "/fhir/DocumentReference", params=filters)
    
    def get_document_reference(self, duuid: str) -> dict:
        """Get details of a specific document reference by UUID.
        
        :param duuid: The UUID of the document reference to retrieve.
        
        :return: Dict JSON response containing the document reference details.
        """
        if not duuid:
            raise ValueError("Document Reference UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/DocumentReference/{duuid}")
    
    def create_document_reference(self, patient: str, data: dict) -> dict:
        """Create a new document reference for a specific patient.
        
        :param patient: The UUID of the patient for whom to create the document reference.
        :param data: Dict containing document reference data to create.
        
        :return: Dict JSON response containing the created document reference details.
        """
        if not patient:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Document Reference data cannot be empty.")
        
        return self._request("POST", f"/fhir/DocumentReference/$docref", json=data)
    
    # -------------------------------
    # fhir/Binary
    # ------------------------------- 
    def download_binary(self, buuid: str) -> bytes:
        """Download a binary resource by UUID.
        
        :param buuid: The UUID of the binary resource to download.
        
        :return: Bytes of the binary resource.
        """
        if not buuid:
            raise ValueError("Binary UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Binary/{buuid}", stream=True).content

    # -------------------------------
    # fhir/Encounter
    # ------------------------------- 
    def list_encounters(self, **filters) -> dict:
        """List encounters with optional filters.
        
        :param filters: Optional query parameters to filter the encounter list.
        
        :return: Dict JSON response containing the list of encounters.
        """
        
        return self._request("GET", "/fhir/Encounter", params=filters)

    def get_encounter(self, euuid: str) -> dict:
        """Get details of a specific encounter by UUID.
        
        :param euuid: The UUID of the encounter to retrieve.
        
        :return: Dict JSON response containing the encounter details.
        """
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Encounter/{euuid}")
    
    # -------------------------------
    # fhir/Goal
    # ------------------------------- 
    def list_goals(self, **filters) -> dict:
        """List goals with optional filters.
        
        :param filters: Optional query parameters to filter the goal list.
        
        :return: Dict JSON response containing the list of goals.
        """
        
        return self._request("GET", "/fhir/Goal", params=filters)
    
    def get_goal(self, guuid: str) -> dict:
        """Get details of a specific goal by UUID.
        
        :param guuid: The UUID of the goal to retrieve.
        
        :return: Dict JSON response containing the goal details.
        """
        if not guuid:
            raise ValueError("Goal UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Goal/{guuid}")
    
    # -------------------------------
    # fhir/Group
    # ------------------------------- 
    def list_groups(self, **filters) -> dict:
        """List groups with optional filters.
        
        :param filters: Optional query parameters to filter the group list.
        
        :return: Dict JSON response containing the list of groups.
        """
        
        return self._request("GET", "/fhir/Group", params=filters)

    def get_group(self, guuid: str) -> dict:
        """Get details of a specific group by UUID.
        
        :param guuid: The UUID of the group to retrieve.
        
        :return: Dict JSON response containing the group details.
        """
        if not guuid:
            raise ValueError("Group UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Group/{guuid}")
    
    def export_group(self, guuid: str) -> dict:
        """Export a group by UUID.
        
        :param guuid: The UUID of the group to export.
        
        :return: Dict JSON response containing the exported group data.
        """
        if not guuid:
            raise ValueError("Group UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Group/{guuid}/$export")

    # -------------------------------
    # fhir/Immunization
    # ------------------------------- 
    def list_immunizations(self, **filters) -> dict:
        """List immunizations with optional filters.
        
        :param filters: Optional query parameters to filter the immunization list.
        
        :return: Dict JSON response containing the list of immunizations.
        """
        
        return self._request("GET", "/fhir/Immunization", params=filters)

    def get_immunization(self, iuuid: str) -> dict:
        """Get details of a specific immunization by UUID.
        
        :param iuuid: The UUID of the immunization to retrieve.
        
        :return: Dict JSON response containing the immunization details.
        """
        if not iuuid:
            raise ValueError("Immunization UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Immunization/{iuuid}")

    # -------------------------------
    # fhir/Location
    # ------------------------------- 
    def list_locations(self, **filters) -> dict:
        """List locations with optional filters.
        
        :param filters: Optional query parameters to filter the location list.
        
        :return: Dict JSON response containing the list of locations.
        """
        
        return self._request("GET", "/fhir/Location", params=filters)

    def get_location(self, luuid: str) -> dict:
        """Get details of a specific location by UUID.
        
        :param luuid: The UUID of the location to retrieve.
        
        :return: Dict JSON response containing the location details.
        """
        if not luuid:
            raise ValueError("Location UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Location/{luuid}")

    # -------------------------------
    # fhir/Medication
    # ------------------------------- 
    def list_medications(self, **filters) -> dict:
        """List medications with optional filters.
        
        :param filters: Optional query parameters to filter the medication list.
        
        :return: Dict JSON response containing the list of medications.
        """
        
        return self._request("GET", "/fhir/Medication", params=filters)

    def get_medication(self, muuid: str) -> dict:
        """Get details of a specific medication by UUID.
        
        :param muuid: The UUID of the medication to retrieve.
        
        :return: Dict JSON response containing the medication details.
        """
        if not muuid:
            raise ValueError("Medication UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Medication/{muuid}")
    
    def list_medication_requests(self, **filters) -> dict:
        """List medication requests with optional filters.
        
        :param filters: Optional query parameters to filter the medication request list.
        
        :return: Dict JSON response containing the list of medication requests.
        """
        
        return self._request("GET", "/fhir/MedicationRequest", params=filters)

    def get_medication_request(self, muuid: str) -> dict:
        """Get details of a specific medication request by UUID.
        
        :param muuid: The UUID of the medication request to retrieve.
        
        :return: Dict JSON response containing the medication request details.
        """
        if not muuid:
            raise ValueError("Medication Request UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/MedicationRequest/{muuid}")

    def get_facility(self, fuuid: str) -> dict:
        """Get details of a specific facility by UUID.
        :param fuuid: The UUID of the facility to retrieve.
        :return: Dict JSON response containing the facility details.
        """
        if not fuuid:
            raise ValueError("Facility UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Facility/{fuuid}")

    # -------------------------------
    # fhir/Observation
    # ------------------------------- 
    def list_observations(self, **filters) -> dict:
        """List observations with optional filters.
        
        :param filters: Optional query parameters to filter the observation list.
        
        :return: Dict JSON response containing the list of observations.
        """
        
        return self._request("GET", "/fhir/Observation", params=filters)

    def get_observation(self, ouuid: str) -> dict:
        """Get details of a specific observation by UUID.
        
        :param ouuid: The UUID of the observation to retrieve.
        
        :return: Dict JSON response containing the observation details.
        """
        if not ouuid:
            raise ValueError("Observation UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Observation/{ouuid}")

    # -------------------------------
    # fhir/Organization
    # ------------------------------- 
    def list_organizations(self, **filters) -> dict:
        """List organizations with optional filters.
        
        :param filters: Optional query parameters to filter the organization list.
        
        :return: Dict JSON response containing the list of organizations.
        """
        
        return self._request("GET", "/fhir/Organization", params=filters)

    def get_organization(self, ouuid: str) -> dict:
        """Get details of a specific organization by UUID.
        
        :param ouuid: The UUID of the organization to retrieve.
        
        :return: Dict JSON response containing the organization details.
        """
        if not ouuid:
            raise ValueError("Organization UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Organization/{ouuid}")

    def create_organization(self, ouuid: str, data: dict) -> dict:
        """Create a new organization.
        
        :param ouuid: The UUID of the organization to create.
        :param data: Dict containing organization data to create.
        
        :return: Dict JSON response containing the created organization details.
        
        """
        if not data:
            raise ValueError("Organization data cannot be empty.")

        return self._request("POST", f"/fhir/Organization/{ouuid}", json=data)

    # -------------------------------
    # fhir/Patient
    # ------------------------------- 
    def list_patients(self, **filters) -> dict:
        """List patients with optional filters.
        
        :param filters: Optional query parameters to filter the patient list.
        
        :return: Dict JSON response containing the list of patients.
        """
        
        return self._request("GET", "/fhir/Patient", params=filters)
    
    def create_patient(self, puuid: str, data: dict) -> dict:
        """Create a new patient.
        
        :param puuid: The UUID of the patient to create.
        :param data: Dict containing patient data to create.
        
        :return: Dict JSON response containing the created patient details.
        """
        if not data:
            raise ValueError("Patient data cannot be empty.")
        
        return self._request("POST", f"/fhir/Patient/{puuid}", json=data)

    # -------------------------------
    # fhir/Person
    # ------------------------------- 
    def list_persons(self, **filters) -> dict:
        """List persons with optional filters.
        
        :param filters: Optional query parameters to filter the person list.
        
        :return: Dict JSON response containing the list of persons.
        """
        
        return self._request("GET", "/fhir/Person", params=filters)

    def get_person(self, puuid: str) -> dict:
        """Get details of a specific person by UUID.
        
        :param puuid: The UUID of the person to retrieve.
        
        :return: Dict JSON response containing the person details.
        """
        if not puuid:
            raise ValueError("Person UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Person/{puuid}")

    # -------------------------------
    # fhir/Practicioner
    # ------------------------------- 
    def list_practitioners(self, **filters) -> dict:
        """List practitioners with optional filters.
        
        :param filters: Optional query parameters to filter the practitioner list.
        
        :return: Dict JSON response containing the list of practitioners.
        """
        
        return self._request("GET", "/fhir/Practitioner", params=filters)

    def get_practitioner(self, pruuid: str) -> dict:
        """Get details of a specific practitioner by UUID.
        
        :param pruuid: The UUID of the practitioner to retrieve.
        
        :return: Dict JSON response containing the practitioner details.
        """
        if not pruuid:
            raise ValueError("Practitioner UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Practitioner/{pruuid}")

    def create_practitioner(self, data: dict) -> dict:
        """Create a new practitioner.
        
        :param data: Dict containing practitioner data to create.
        
        :return: Dict JSON response containing the created practitioner details.
        """
        if not data:
            raise ValueError("Practitioner data cannot be empty.")
        
        return self._request("POST", "/fhir/Practitioner", json=data)

    def update_practitioner(self, pruuid: str, data: dict) -> dict:
        """Update an existing practitioner.
        
        :param pruuid: The UUID of the practitioner to update.
        :param data: Dict containing updated practitioner data.
        
        :return: Dict JSON response containing the updated practitioner details.
        """
        if not pruuid:
            raise ValueError("Practitioner UUID cannot be empty.")
        if not data:
            raise ValueError("Practitioner data cannot be empty.")
        
        return self._request("PUT", f"/fhir/Practitioner/{pruuid}", json=data)

    def get_practitioner_roles(self, **filters) -> dict:
        """Get roles of a specific practitioner by UUID.
        
        :pram pruuid: The UUID of the practitioner to retrieve roles for.
        
        :return: Dict JSON response containing the practitioner's roles.
        """
                
        return self._request("GET", f"/fhir/PractitionerRole", params=filters)

    def get_practitioner_role(self, pruuid: str) -> dict:
        """Get details of a specific practitioner role by UUID.
        
        :param pruuid: The UUID of the practitioner role to retrieve.
        
        :return: Dict JSON response containing the practitioner role details.
        """
        if not pruuid:
            raise ValueError("Practitioner Role UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/PractitionerRole/{pruuid}")

    def create_facility(self, data: dict) -> dict:
        """Create a new facility.
        
        :param data: Dict containing facility data to create.
        :return: Dict JSON response containing the created facility details.
        
        """
        if not data:
            raise ValueError("Facility data cannot be empty.")

        return self._request("POST", "/fhir/Facility", json=data)
    
    # -------------------------------
    # fhir/Procedure
    # ------------------------------- 
    def list_procedures(self, **filters) -> dict:
        """List procedures with optional filters.
        
        :param filters: Optional query parameters to filter the procedure list.
        
        :return: Dict JSON response containing the list of procedures.
        """
        
        return self._request("GET", "/fhir/Procedure", params=filters)

    def get_procedure(self, puuid: str) -> dict:
        """Get details of a specific procedure by UUID.
        
        :param puuid: The UUID of the procedure to retrieve.
        
        :return: Dict JSON response containing the procedure details.
        """
        if not puuid:
            raise ValueError("Procedure UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Procedure/{puuid}")
    
    # -------------------------------
    # fhir/Provenance
    # ------------------------------- 
    def list_provenances(self, **filters) -> dict:
        """List provenances with optional filters.
        
        :param filters: Optional query parameters to filter the provenance list.
        
        :return: Dict JSON response containing the list of provenances.
        """
        
        return self._request("GET", "/fhir/Provenance", params=filters)
    
    def get_provenance(self, puuid: str) -> dict:   
        """Get details of a specific provenance by UUID.
        
        :param puuid: The UUID of the provenance to retrieve.
        
        :return: Dict JSON response containing the provenance details.
        """
        if not puuid:
            raise ValueError("Provenance UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/Provenance/{puuid}")

    # -------------------------------
    # fhir/ValueSet
    # ------------------------------- 
    def list_value_sets(self, **filters) -> dict:
        """List value sets with optional filters.
        
        :param filters: Optional query parameters to filter the value set list.
        
        :return: Dict JSON response containing the list of value sets.
        """
        
        return self._request("GET", "/fhir/ValueSet", params=filters)

    def get_value_set(self, vsuuid: str) -> dict:
        """Get details of a specific value set by UUID.
        
        :param vsuuid: The UUID of the value set to retrieve.
        
        :return: Dict JSON response containing the value set details.
        """
        if not vsuuid:
            raise ValueError("Value Set UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/ValueSet/{vsuuid}")

    # -------------------------------
    # fhir/metadata
    # ------------------------------- 
    def get_metadata(self) -> dict: 
        """get metadata of the OpenEMR FHIR server.
        
        :return: Dict JSON response containing the list of metadata.
        """
        
        return self._request("GET", "/fhir/metadata")

    # -------------------------------
    # fhir/OpterationDefinition
    # ------------------------------- 
    def list_operation_definitions(self, **filters) -> dict:
        """List operation definitions with optional filters.
        
        :param filters: Optional query parameters to filter the operation definition list.
        
        :return: Dict JSON response containing the list of operation definitions.
        """
        
        return self._request("GET", "/fhir/OperationDefinition", params=filters)
    
    def get_operation_definition(self, ouuid: str) -> dict:
        """Get details of a specific operation definition by UUID.
        
        :param ouuid: The UUID of the operation definition to retrieve.
        
        :return: Dict JSON response containing the operation definition details.
        """
        if not ouuid:
            raise ValueError("Operation Definition UUID cannot be empty.")
        
        return self._request("GET", f"/fhir/OperationDefinition/{ouuid}")

    # -------------------------------
    # fhir/bulk 
    # ------------------------------- 
    def export_fhir_data(self) -> dict:
        """Bulk export FHIR data 
      
        :return: Dict JSON response containing the exported FHIR data.
        """
        
        return self._request("GET", f"/fhir/$export")

    def bulk_data_status(self, job_id: str) -> dict:
        """Check the status of a bulk data export job.
                
        :return: Dict JSON response containing the status of the bulk data export job.
        """
        
        return self._request("GET", f"/fhir/$bulkdata-status")
    
    def delete_bulk_data_status(self) -> dict:
        """Delete the status of a bulk data export job.
        
        :return: Dict JSON response confirming the deletion of the bulk data export job status.
        """

        return self._request("DELETE", f"/fhir/$bulkdata-status")
    
    # -------------------------------
    # api/facility 
    # ------------------------------- 

    def list_facilities(self, **filters) -> dict:
        """List facilities with optional filters.
        :param filters: Optional query parameters to filter the facility list.

        :return: Dict JSON response containing the list of facilities.
        """

        return self._request("GET", "/api/facility", params=filters)

    def create_facility(self, data: dict) -> dict:
        """Create a new facility.
        
        :param data: Dict containing facility data to create.
        
        :return: Dict JSON response containing the created facility details.
        """
        if not data:
            raise ValueError("Facility data cannot be empty.")

        return self._request("POST", "/api/facility", json=data)

    def get_facility(self, fuuid: str) -> dict:
        """Get details of a specific facility by ID.
        
        :param fuuid: The ID of the facility to retrieve.
        
        :return: Dict JSON response containing the facility details.
        """
        if not fuuid:
            raise ValueError("Facility ID cannot be empty.")
        
        return self._request("GET", f"/api/facility/{fuuid}")

    def update_facility(self, fuuid: str, data: dict) -> dict:
        """Update an existing facility.
        
        :param fuuid: The ID of the facility to update.
        :param data: Dict containing updated facility data.
        
        :return: Dict JSON response containing the updated facility details.
        """
        if not fuuid:
            raise ValueError("Facility ID cannot be empty.")
        if not data:
            raise ValueError("Facility data cannot be empty.")
        
        return self._request("PUT", f"/api/facility/{fuuid}", json=data)

    # -------------------------------
    # api/patients
    # -------------------------------
    def list_patients(self, **filters) -> dict:
        """List patients with optional filters.
        
        See OpenEMR API documentation for available filters.

        :param filters: Optional query parameters to filter the patient list.
        
        :return: JSON response containing the list of patients.
        """
        
        return self._request("GET", "/api/patient", params=filters)
    
    def create_patient(self, data: dict) -> dict:
        """Update an existing patient.
        
        :param data: Dict containing updated patient data.
        
        :return: JSON response containing the updated patient details.
        """

        if not data:
            raise ValueError("Patient data cannot be empty.")
        
        return self._request("POST", f"/api/patient", json=data)

    def get_patient(self, puuid: str) -> dict:
        """Get details of a specific patient by UUID.
        
        :param puuid: The UUID of the patient to retrieve.
        
        :return: JSON response containing the patient details.
        """
        
        return self._request("GET", f"/api/patient/{puuid}")

    def update_patient(self, puuid:str, data: dict) -> dict:
        """Update a patient.

        :param puuid: The UUID of the patient to update.
        :param data: Dict containing patient data to update.
        
        :return: JSON response containing the created patient details.
        """

        return self._request("PUT", f"/api/patient{puuid}", json=data)

    def get_patient_encounters(self, puuid: str) -> dict:
        """Get encounters for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose encounters to retrieve.
        
        :return: JSON response containing the patient's encounters.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/encounters")
    
    def create_patient_encounter(self, puuid: str, data: dict) -> dict:
        """Create a new encounter for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the encounter.
        :param data: Dict containing encounter data to create.
        
        :return: JSON response containing the created encounter details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Encounter data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/encounter", json=data)
    
    def get_patient_encounters_by_encounter(self, puuid: str, euuid: str) -> dict:
        """Get details of a specific encounter for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter to retrieve.
        :param euuid: The UUID of the encounter to retrieve.
        
        :return: JSON response containing the encounter details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/encounter/{euuid}")

    def update_patient_encounter(self, puuid: str, euuid: str, data: dict) -> dict:
        """Update an existing encounter for a specific patient.
        
        :param puuid: The UUID of the patient whose encounter to update.
        :param euuid: The UUID of the encounter to update.
        :param data: Dict containing updated encounter data.
        
        :return: JSON response containing the updated encounter details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        if not data:
            raise ValueError("Encounter data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/encounter/{euuid}", json=data)

    def get_patient_encounter_soap(self, puuid: str, euuid: str) -> dict:
        """Get SOAP notes for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter SOAP notes to retrieve.
        :param euuid: The UUID of the encounter whose SOAP notes to retrieve.
        
        :return: JSON response containing the SOAP notes.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/encounter/{euuid}/soap_note")
    
    def update_patient_encounter_soap(self, puuid: str, euuid: str, data: dict) -> dict:
        """Update SOAP notes for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter SOAP notes to update.
        :param euuid: The UUID of the encounter whose SOAP notes to update.
        :param data: Dict containing updated SOAP note data.
        
        :return: JSON response containing the updated SOAP notes.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        if not data:
            raise ValueError("SOAP note data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/encounter/{euuid}/soap_note", json=data)

    def list_patient_encounter_vital(self, puuid: str, euuid: str) -> dict:
        """Get vitals for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter vitals to retrieve.
        :param euuid: The UUID of the encounter whose vitals to retrieve.
        
        :return: JSON response containing the vitals.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/encounter/{euuid}/vital")

    def create_patient_encounter_vital(self, puuid: str, euuid: str, data: dict) -> dict:
        """Create vitals for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter vitals to create.
        :param euuid: The UUID of the encounter whose vitals to create.
        :param data: Dict containing vital data to create.
        
        :return: JSON response containing the created vitals.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        if not data:
            raise ValueError("Vital data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/encounter/{euuid}/vital", json=data)

    def get_patient_encounter_vital(self, puuid: str, euuid: str, vid: str) -> dict:
        """Get details of a specific vital for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter vital to retrieve.
        :param euuid: The UUID of the encounter whose vital to retrieve.
        :param vid: The ID of the vital to retrieve.
        
        :return: JSON response containing the vital details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        if not vid:
            raise ValueError("Vital ID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/encounter/{euuid}/vital/{vid}")

    def update_patient_encounter_vital(self, puuid: str, euuid: str, vid: str, data: dict) -> dict:
        """Update a specific vital for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter vital to update.
        :param euuid: The UUID of the encounter whose vital to update.
        :param vid: The ID of the vital to update.
        :param data: Dict containing updated vital data.
        
        :return: JSON response containing the updated vital details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        if not vid:
            raise ValueError("Vital ID cannot be empty.")
        if not data:
            raise ValueError("Vital data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/encounter/{euuid}/vital/{vid}", json=data)  

    def get_patient_encounter_soap(self, puuid: str, euuid: str, sid: str) -> dict:
        """Get SOAP notes for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter SOAP notes to retrieve.
        :param euuid: The UUID of the encounter whose SOAP notes to retrieve.
        :param sid: The ID of the SOAP note to retrieve.
        
        :return: JSON response containing the SOAP notes.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/encounter/{euuid}/soap_note/{sid}")
    
    def update_patient_encounter_soap(self, puuid: str, euuid: str, sid: str, data: dict) -> dict:
        """Update SOAP notes for a specific encounter of a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose encounter SOAP notes to update.
        :param euuid: The UUID of the encounter whose SOAP notes to update.
        :param sid: The ID of the SOAP note to update.
        :param data: Dict containing updated SOAP note data.
        
        :return: JSON response containing the updated SOAP notes.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        if not data:
            raise ValueError("SOAP note data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/encounter/{euuid}/soap_note/{sid}", json=data)

    def list_patient_medical_problem(self, puuid: str) -> dict:
        """Get medical problems for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose medical problems to retrieve.
        
        :return: JSON response containing the patient's medical problems.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/medical_problem")

    def create_patient_medical_problem(self, puuid: str, data: dict) -> dict:
        """Create a new medical problem for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the medical problem.
        :param data: Dict containing medical problem data to create.
        
        :return: JSON response containing the created medical problem details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Medical Problem data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/medical_problem", json=data)
    
    def get_patient_medical_problem(self, puuid: str, mpuuid: str) -> dict:
        """Get details of a specific medical problem for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose medical problem to retrieve.
        :param mpuuid: The UUID of the medical problem to retrieve.
        
        :return: JSON response containing the medical problem details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mpuuid:
            raise ValueError("Medical Problem UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/medical_problem/{mpuuid}")
    
    def update_patient_medical_problem(self, puuid: str, mpuuid: str, data: dict) -> dict:
        """Update a specific medical problem for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose medical problem to update.
        :param mpuuid: The UUID of the medical problem to update.
        :param data: Dict containing updated medical problem data.
        
        :return: JSON response containing the updated medical problem details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mpuuid:
            raise ValueError("Medical Problem UUID cannot be empty.")
        if not data:
            raise ValueError("Medical Problem data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/medical_problem/{mpuuid}", json=data)

    def delete_patient_medical_problem(self, puuid: str, mpuuid: str) -> dict:
        """Delete a specific medical problem for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose medical problem to delete.
        :param mpuuid: The UUID of the medical problem to delete.
        
        :return: JSON response confirming the deletion of the medical problem.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mpuuid:
            raise ValueError("Medical Problem UUID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/medical_problem/{mpuuid}")
    
    def list_patient_allergies(self, puuid: str) -> dict:
        """Get allergies for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose allergies to retrieve.
        
        :return: JSON response containing the patient's allergies.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/allergy")
    
    def create_patient_allergy(self, puuid: str, data: dict) -> dict:
        """Create a new allergy for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the allergy.
        :param data: Dict containing allergy data to create.
        
        :return: JSON response containing the created allergy details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Allergy data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/allergy", json=data)

    def get_patient_allergy(self, puuid: str, auuid: str) -> dict:
        """Get details of a specific allergy for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose allergy to retrieve.
        :param auuid: The UUID of the allergy to retrieve.
        
        :return: JSON response containing the allergy details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not auuid:
            raise ValueError("Allergy UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/allergy/{auuid}")

    def update_patient_allergy(self, puuid: str, auuid: str, data: dict) -> dict:   
        """Update a specific allergy for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose allergy to update.
        :param auuid: The UUID of the allergy to update.
        :param data: Dict containing updated allergy data.
        
        :return: JSON response containing the updated allergy details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not auuid:
            raise ValueError("Allergy UUID cannot be empty.")
        if not data:
            raise ValueError("Allergy data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/allergy/{auuid}", json=data)

    def delete_patient_allergy(self, puuid: str, auuid: str) -> dict:
        """Delete a specific allergy for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose allergy to delete.
        :param auuid: The UUID of the allergy to delete.
        
        :return: JSON response confirming the deletion of the allergy.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not auuid:
            raise ValueError("Allergy UUID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/allergy/{auuid}")

    def list_patient_medications(self, puuid: str) -> dict:
        """Get medications for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose medications to retrieve.
        
        :return: JSON response containing the patient's medications.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/medication")
    
    def create_patient_medication(self, puuid: str, data: dict) -> dict:
        """Create a new medication for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the medication.
        :param data: Dict containing medication data to create.
        
        :return: JSON response containing the created medication details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Medication data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/medication", json=data) 
    
    def get_patient_medication(self, puuid: str, mid: str) -> dict:
        """Get details of a specific medication for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose medication to retrieve.
        :param mid: The ID of the medication to retrieve.
        
        :return: JSON response containing the medication details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mid:
            raise ValueError("Medication ID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/medication/{mid}")   
    
    def update_patient_medication(self, puuid: str, mid: str, data: dict) -> dict:
        """Update a specific medication for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose medication to update.
        :param mid: The ID of the medication to update.
        :param data: Dict containing updated medication data.
        
        :return: JSON response containing the updated medication details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mid:
            raise ValueError("Medication ID cannot be empty.")
        if not data:
            raise ValueError("Medication data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/medication/{mid}", json=data)    
    
    def delete_patient_medication(self, puuid: str, mid: str) -> dict:
        """Delete a specific medication for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose medication to delete.
        :param mid: The ID of the medication to delete.
        
        :return: JSON response confirming the deletion of the medication.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mid:
            raise ValueError("Medication ID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/medication/{mid}")

    def list_patient_surgeries(self, puuid: str) -> dict:
        """Get surgeries for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose surgeries to retrieve.
        
        :return: JSON response containing the patient's surgeries.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/surgery")
    
    def create_patient_surgery(self, puuid: str, data: dict) -> dict:
        """Create a new surgery for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the surgery.
        :param data: Dict containing surgery data to create.
        
        :return: JSON response containing the created surgery details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Surgery data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/surgery", json=data)

    def get_patient_surgery(self, puuid: str, suuid: str) -> dict:
        """Get details of a specific surgery for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose surgery to retrieve.
        :param suuid: The UUID of the surgery to retrieve.
        
        :return: JSON response containing the surgery details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not suuid:
            raise ValueError("Surgery UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/surgery/{suuid}")

    def update_patient_surgery(self, puuid: str, suuid: str, data: dict) -> dict:   
        """Update a specific surgery for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose surgery to update.
        :param suuid: The UUID of the surgery to update.
        :param data: Dict containing updated surgery data.
        
        :return: JSON response containing the updated surgery details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not suuid:
            raise ValueError("Surgery UUID cannot be empty.")
        if not data:
            raise ValueError("Surgery data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/surgery/{suuid}", json=data)

    def delete_patient_surgery(self, puuid: str, suuid: str) -> dict:
        """Delete a specific surgery for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose surgery to delete.
        :param suuid: The UUID of the surgery to delete.
        
        :return: JSON response confirming the deletion of the surgery.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not suuid:
            raise ValueError("Surgery UUID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/surgery/{suuid}")

    def list_patient_dental_issues(self, puuid: str) -> dict:
        """Get dental issues for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose dental issues to retrieve.
        
        :return: JSON response containing the patient's dental issues.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/dental_issue")

    def create_patient_dental_issue(self, puuid: str, data: dict) -> dict:
        """Create a new dental issue for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the dental issue.
        :param data: Dict containing dental issue data to create.
        
        :return: JSON response containing the created dental issue details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Dental Issue data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/dental_issue", json=data)

    def get_patient_dental_issue(self, puuid: str, duuid: str) -> dict:
        """Get details of a specific dental issue for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose dental issue to retrieve.
        :param duuid: The UUID of the dental issue to retrieve.
        
        :return: JSON response containing the dental issue details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not duuid:
            raise ValueError("Dental Issue UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/dental_issue/{duuid}")

    def update_patient_dental_issue(self, puuid: str, duuid: str, data: dict) -> dict:   
        """Update a specific dental issue for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose dental issue to update.
        :param duuid: The UUID of the dental issue to update.
        :param data: Dict containing updated dental issue data.
        
        :return: JSON response containing the updated dental issue details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not duuid:
            raise ValueError("Dental Issue UUID cannot be empty.")
        if not data:
            raise ValueError("Dental Issue data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/dental_issue/{duuid}", json=data)

    def delete_patient_dental_issue(self, puuid: str, duuid: str) -> dict:
        """Delete a specific dental issue for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose dental issue to delete.
        :param duuid: The UUID of the dental issue to delete.
        
        :return: JSON response confirming the deletion of the dental issue.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not duuid:
            raise ValueError("Dental Issue UUID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/dental_issue/{duuid}")

    def list_patient_appointments(self, puuid: str) -> dict:
        """Get appointments for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose appointments to retrieve.
        
        :return: JSON response containing the patient's appointments.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/appointment")

    def create_patient_appointment(self, puuid: str, data: dict) -> dict:
        """Create a new appointment for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the appointment.
        :param data: Dict containing appointment data to create.
        
        :return: JSON response containing the created appointment details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Appointment data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/appointment", json=data)

    def list_patient_documents(self, puuid: str) -> dict:
        """Get documents for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose documents to retrieve.
        
        :return: JSON response containing the patient's documents.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/document")
    
    def create_patient_document(self, puuid: str, data: dict) -> dict:
        """Create a new document for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the document.
        :param data: Dict containing document data to create.
        
        :return: JSON response containing the created document details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Document data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/document", json=data)
    
    def get_patient_document(self, puuid: str, duuid: str) -> dict:
        """Get details of a specific document for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose document to retrieve.
        :param duuid: The UUID of the document to retrieve.
        
        :return: JSON response containing the document details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not duuid:
            raise ValueError("Document UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/document/{duuid}")
    
    def list_patient_employers(self, puuid: str) -> dict:
        """Get employers for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose employers to retrieve.
        
        :return: JSON response containing the patient's employers.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/employer")
    
    def list_patient_insurances(self, puuid: str) -> dict:
        """Get insurances for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose insurances to retrieve.
        
        :return: JSON response containing the patient's insurances.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/insurance")
    
    def create_patient_insurance(self, puuid: str, data: dict) -> dict:
        """Create a new insurance for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the insurance.
        :param data: Dict containing insurance data to create.
        
        :return: JSON response containing the created insurance details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Insurance data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/insurance", json=data)
    
    def patient_insurance_swap(self, puuid: str, data: dict) -> dict:
        """Swap details for a specific patient insurance by UUID.
        
        :param puuid: The UUID of the patient whose insurance swap details to retrieve.
        :param data: Dict containing insurance swap data.

        :return: JSON response containing the insurance swap details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/insurance/$swap-insurance", json=data)
    
    def list_patient_insurance(self, puuid: str) -> dict:
        """Get insurances for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose insurances to retrieve.
        
        :return: JSON response containing the patient's insurances.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/insurance")

    def update_patient_insurance(self, puuid: str, iuuid: str, data: dict) -> dict:
        """Update a specific insurance for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose insurance to update.
        :param iuuid: The UUID of the insurance to update.
        :param data: Dict containing updated insurance data.
        
        :return: JSON response containing the updated insurance details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not iuuid:
            raise ValueError("Insurance UUID cannot be empty.")
        if not data:
            raise ValueError("Insurance data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/insurance/{iuuid}", json=data)

    def create_patient_message(self, puuid: str, data: dict) -> dict:
        """Create a new message for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the message.
        :param data: Dict containing message data to create.
        
        :return: JSON response containing the created message details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Message data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/message", json=data)

    def list_patient_transactions(self, puuid: str) -> dict:
        """Get transactions for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose transactions to retrieve.
        
        :return: JSON response containing the patient's transactions.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/transaction")

    def create_patient_transaction(self, puuid: str, data: dict) -> dict:
        """Create a new transaction for a specific patient.
        
        :param puuid: The UUID of the patient for whom to create the transaction.
        :param data: Dict containing transaction data to create.
        
        :return: JSON response containing the created transaction details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not data:
            raise ValueError("Transaction data cannot be empty.")
        
        return self._request("POST", f"/api/patient/{puuid}/transaction", json=data)

    # -------------------------------
    # api/practitioner 
    # ------------------------------- 

    def list_practitioners(self, **filters) -> dict:
        """List practitioners with optional filters.
        
        :param filters: Optional query parameters to filter the practitioner list.
        
        :return: Dict JSON response containing the list of practitioners.
        """

        return self._request("GET", "/api/practitioner", params=filters)
    
    def create_practitioner(self, data: dict) -> dict:
        """Create a new practitioner.
        
        :param data: Dict containing practitioner data to create.
        
        :return: Dict JSON response containing the created practitioner details.
        """
        if not data:
            raise ValueError("Practitioner data cannot be empty.")

        return self._request("POST", "/api/practitioner", json=data)

    def get_practitioner(self, puuid: str) -> dict:
        """Get details of a specific practitioner by UUID.
        
        :param puuid: The UUID of the practitioner to retrieve.
        
        :return: Dict JSON response containing the practitioner details.
        """
        if not puuid:
            raise ValueError("Practitioner UUID cannot be empty.")
        
        return self._request("GET", f"/api/practitioner/{puuid}")
    
    def update_practitioner(self, puuid:str, data: dict) -> dict:
        """Update a practitioner.

        :param puuid: The UUID of the practitioner to update.
        :param data: Dict containing practitioner data to update.
        
        :return: Dict JSON response containing the created practitioner details.
        """

        if not puuid:
            raise ValueError("Practitioner UUID cannot be empty.")
        if not data:
            raise ValueError("Practitioner data cannot be empty.")
        
        return self._request("PUT", f"/api/practitioner/{puuid}", json=data)

    def get_patient_appointments(self, puuid: str) -> dict:
        """Get appointments for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose appointments to retrieve.
        
        :return: JSON response containing the patient's appointments.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/api/patient/{puuid}/appointment")

    def delete_patient_appointment(self, puuid: str, eid: str) -> dict:
        """Delete a specific appointment for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose appointment to delete.
        :param eid: The UUID of the appointment to delete.
        
        :return: JSON response confirming the deletion of the appointment.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not eid:
            raise ValueError("Appointment UUID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/appointment/{eid}")

    def update_patient_message(self, puuid: str, mid: str, data: dict) -> dict:
        """Update a specific message for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose message to update.
        :param mid: The UUID of the message to update.
        :param data: Dict containing updated message data.
        
        :return: JSON response containing the updated message details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mid:
            raise ValueError("Message UUID cannot be empty.")
        if not data:
            raise ValueError("Message data cannot be empty.")
        
        return self._request("PUT", f"/api/patient/{puuid}/message/{mid}", json=data)

    def delete_patient_message(self, puuid: str, mid: str) -> dict:
        """Delete a specific message for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose message to delete.
        :param mid: The UUID of the message to delete.
        
        :return: JSON response confirming the deletion of the message.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not mid:
            raise ValueError("Message UUID cannot be empty.")
        
        return self._request("DELETE", f"/api/patient/{puuid}/message/{mid}")

    # -------------------------------
    # api/medical_problem
    # ------------------------------- 

    def list_medical_problems(self, **filters) -> dict:
        """List medical problems with optional filters.
        
        :param filters: Optional query parameters to filter the medical problem list.
        
        :return: Dict JSON response containing the list of medical problems.
        """

        return self._request("GET", "/api/medical_problem", params=filters)

    def get_medical_problem(self, mpuuid: str) -> dict:
        """Get details of a specific medical problem by UUID.
        
        :param mpuuid: The UUID of the medical problem to retrieve.
        
        :return: Dict JSON response containing the medical problem details.
        """
        if not mpuuid:
            raise ValueError("Medical Problem UUID cannot be empty.")
        
        return self._request("GET", f"/api/medical_problem/{mpuuid}")

    # -------------------------------
    # api/allergy
    # ------------------------------- 
    
    def list_allergies(self, **filters) -> dict:
        """List allergies with optional filters.
        
        :param filters: Optional query parameters to filter the allergy list.
        
        :return: Dict JSON response containing the list of allergies.
        """

        return self._request("GET", "/api/allergy", params=filters)

    def get_allergy(self, auuid: str) -> dict:
        """Get details of a specific allergy by UUID.
        
        :param auuid: The UUID of the allergy to retrieve.
        
        :return: Dict JSON response containing the allergy details.
        """
        if not auuid:
            raise ValueError("Allergy UUID cannot be empty.")
        
        return self._request("GET", f"/api/allergy/{auuid}")
    
    # -------------------------------
    # api/appointment
    # ------------------------------- 

    def list_appointments(self, **filters) -> dict:
        """List appointments with optional filters.
        
        :param filters: Optional query parameters to filter the appointment list.
        
        :return: Dict JSON response containing the list of appointments.
        """

        return self._request("GET", "/api/appointment", params=filters)
    
    def get_appointment(self, auuid: str) -> dict:
        """Get details of a specific appointment by UUID.
        
        :param auuid: The UUID of the appointment to retrieve.
        
        :return: Dict JSON response containing the appointment details.
        """
        if not auuid:
            raise ValueError("Appointment UUID cannot be empty.")
        
        return self._request("GET", f"/api/appointment/{auuid}")

    # -------------------------------
    # api/list
    # ------------------------------- 

    def list(self, list_name: str) -> dict:
        """List items <TODO what does this endpoint do?>.
        
        :param list_name: The name of the list to retrieve items from.
                
        :return: Dict JSON response containing the list items.
        """
        if not list_name:
            raise ValueError("List name cannot be empty.")
        
        return self._request("GET", f"/api/list/{list_name}")

    # -------------------------------
    # api/user
    # ------------------------------- 

    def list_users(self, **filters) -> dict:
        """List users with optional filters.
        
        :param filters: Optional query parameters to filter the user list.
        
        :return: Dict JSON response containing the list of users.
        """

        return self._request("GET", "/api/user", params=filters)
    
    def get_user(self, puuid: str) -> dict:
        """Get details of a specific user by UUID.
        
        :param puuid: The UUID of the user to retrieve.
        
        :return: Dict JSON response containing the user details.
        """
        if not puuid:
            raise ValueError("User UUID cannot be empty.")
        
        return self._request("GET", f"/api/user/{puuid}")
    
    # -------------------------------
    # api/version
    # ------------------------------- 

    def list_versions(self) -> dict:
        """List OpenEMR versions.
        
        :return: Dict JSON response containing the list of OpenEMR versions.
        """

        return self._request("GET", "/api/version") 
    
    # -------------------------------
    # api/product
    # ------------------------------- 

    def list_products(self) -> dict:
        """List products with optional filters.
        
        :return: Dict JSON response containing the list of products.
        """

        return self._request("GET", "/api/product")

    # -------------------------------
    # api/insurance_company
    # ------------------------------- 

    def list_insurance_companies(self, **filters) -> dict:
        """List insurance companies with optional filters.
        
        :param filters: Optional query parameters to filter the insurance company list.
        
        :return: Dict JSON response containing the list of insurance companies.
        """

        return self._request("GET", "/api/insurance_company", params=filters)

    def create_insurance_company(self, data: dict) -> dict:
        """Create a new insurance company.
        
        :param data: Dict containing insurance company data to create.
        
        :return: Dict JSON response containing the created insurance company details.
        """
        if not data:
            raise ValueError("Insurance Company data cannot be empty.")

        return self._request("POST", "/api/insurance_company", json=data)

    def get_insurance_company(self, icuuid: str) -> dict:
        """Get details of a specific insurance company by UUID.
        
        :param icuuid: The UUID of the insurance company to retrieve.
        
        :return: Dict JSON response containing the insurance company details.
        """
        if not icuuid:
            raise ValueError("Insurance Company UUID cannot be empty.")
        
        return self._request("GET", f"/api/insurance_company/{icuuid}")
    
    def update_insurance_company(self, icuuid:str, data: dict) -> dict:
        """Update an insurance company.

        :param icuuid: The UUID of the insurance company to update.
        :param data: Dict containing insurance company data to update.
        
        :return: Dict JSON response containing the created insurance company details.
        """

        if not icuuid:
            raise ValueError("Insurance Company UUID cannot be empty.")
        if not data:
            raise ValueError("Insurance Company data cannot be empty.")
        
        return self._request("PUT", f"/api/insurance_company/{icuuid}", json=data)

    def list_insurance_types(self) -> dict:
        """List insurance types.
        
        :return: Dict JSON response containing the list of insurance types.
        """

        return self._request("GET", "/api/insurance_type")

    # -------------------------------
    # api/transaction 
    # ------------------------------- 

    def update_transaction(self, tuuid: str, data: dict) -> dict:
        """Update a specific transaction for a specific patient by UUIDs.
                
        :param tuuid: The UUID of the transaction to update.
        :param data: Dict containing updated transaction data.
        
        :return: JSON response containing the updated transaction details.
        """
        if not tuuid:
            raise ValueError("Transaction UUID cannot be empty.")
        if not data:
            raise ValueError("Transaction data cannot be empty.")
        
        return self._request("PUT", f"/api/transaction/{tuuid}", json=data)

    # -------------------------------
    # api/immunization 
    # ------------------------------- 

    def list_immunizations(self, **filters) -> dict:
        """List immunizations with optional filters.
        
        :param filters: Optional query parameters to filter the immunization list.
        
        :return: Dict JSON response containing the list of immunizations.
        """

        return self._request("GET", "/api/immunization", params=filters)
    
    def get_immunization(self, iuuid: str) -> dict:
        """Get details of a specific immunization by UUID.
        
        :param iuuid: The UUID of the immunization to retrieve.
        
        :return: Dict JSON response containing the immunization details.
        """
        if not iuuid:
            raise ValueError("Immunization UUID cannot be empty.")
        
        return self._request("GET", f"/api/immunization/{iuuid}")
    
    # -------------------------------
    # api/procedure 
    # ------------------------------- 

    def list_procedures(self, **filters) -> dict:
        """List procedures with optional filters.
        
        :param filters: Optional query parameters to filter the procedure list.
        
        :return: Dict JSON response containing the list of procedures.
        """

        return self._request("GET", "/api/procedure", params=filters)

    def get_procedure(self, puuid: str) -> dict:
        """Get details of a specific procedure by UUID.
        
        :param puuid: The UUID of the procedure to retrieve.
        
        :return: Dict JSON response containing the procedure details.
        """
        if not puuid:
            raise ValueError("Procedure UUID cannot be empty.")
        
        return self._request("GET", f"/api/procedure/{puuid}")

    # -------------------------------
    # api/drug 
    # ------------------------------- 

    def list_drugs(self, **filters) -> dict:
        """List drugs with optional filters.
        
        :param filters: Optional query parameters to filter the drug list.
        
        :return: Dict JSON response containing the list of drugs.
        """

        return self._request("GET", "/api/drug", params=filters)

    def get_drug(self, duuid: str) -> dict:
        """Get details of a specific drug by UUID.
        
        :param duuid: The UUID of the drug to retrieve.
        
        :return: Dict JSON response containing the drug details.
        """
        if not duuid:
            raise ValueError("Drug UUID cannot be empty.")
        
        return self._request("GET", f"/api/drug/{duuid}")

    # -------------------------------
    # api/prescription
    # ------------------------------- 

    def list_prescriptions(self, **filters) -> dict:
        """List prescriptions with optional filters.
        
        :param filters: Optional query parameters to filter the prescription list.
        
        :return: Dict JSON response containing the list of prescriptions.
        """

        return self._request("GET", "/api/prescription", params=filters)

    def get_prescription(self, puuid: str) -> dict:
        """Get details of a specific prescription by UUID.
        
        :param puuid: The UUID of the prescription to retrieve.
        
        :return: Dict JSON response containing the prescription details.
        """
        if not puuid:
            raise ValueError("Prescription UUID cannot be empty.")
        
        return self._request("GET", f"/api/prescription/{puuid}")

    # -------------------------------
    # portal/patient
    # ------------------------------- 

    def list_portal_patients(self) -> dict:
        """List portal patients with optional filters.
        
        :return: Dict JSON response containing the list of portal patients.
        """

        return self._request("GET", "/portal/patient")

    def list_portal_patient_encounters(self) -> dict:
        """List encounters for a specific portal patients.
        
        :return: JSON response containing the portal patient's encounters.
        """
        
        return self._request("GET", f"/portal/patient/encounter")

    def get_portal_patient_encounter(self, euuid: str) -> dict:
        """Get details of a specific encounter for a specific portal patient by UUIDs.
        
        :param euuid: The UUID of the encounter to retrieve.
        
        :return: JSON response containing the encounter details.
        """
        if not euuid:
            raise ValueError("Encounter UUID cannot be empty.")
        
        return self._request("GET", f"/portal/patient/encounter/{euuid}")
    
    def list_patient_appointments(self, puuid: str) -> dict:
        """Get appointments for a specific patient by UUID.
        
        :param puuid: The UUID of the patient whose appointments to retrieve.
        
        :return: JSON response containing the patient's appointments.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        
        return self._request("GET", f"/portal/patient/{puuid}/appointment")

    def get_patient_appointment(self, puuid: str, eid: str) -> dict:
        """Get details of a specific appointment for a specific patient by UUIDs.
        
        :param puuid: The UUID of the patient whose appointment to retrieve.
        :param eid: The UUID of the appointment to retrieve.
        
        :return: JSON response containing the appointment details.
        """
        if not puuid:
            raise ValueError("Patient UUID cannot be empty.")
        if not eid:
            raise ValueError("Appointment UUID cannot be empty.")
        
        return self._request("GET", f"/portal/patient/{puuid}/appointment/{eid}")
