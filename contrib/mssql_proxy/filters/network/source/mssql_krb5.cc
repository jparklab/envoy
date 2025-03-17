#include "mssql_codec.h"
#include "envoy/buffer/buffer.h"

#include "gssapi.h"
#include <cstring>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

std::string format_error(OM_uint32 maj_stat, OM_uint32 min_stat) {
  OM_uint32 msg_ctx = 0;
  OM_uint32 status_code;
  gss_buffer_desc status_string;

  char buffer[1024];
  std::string major_status, minor_status;
  gss_display_status(&status_code, maj_stat, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx,
                     &status_string);
  snprintf(buffer, sizeof(buffer), "Major Status: %s, ", static_cast<char*>(status_string.value));
  major_status = std::string(buffer);
  gss_release_buffer(&status_code, &status_string);

  gss_display_status(&status_code, min_stat, GSS_C_MECH_CODE, GSS_C_NO_OID, &msg_ctx,
                     &status_string);
  snprintf(buffer, sizeof(buffer), "Minor Status: %s", static_cast<char*>(status_string.value));
  minor_status = std::string(buffer);
  gss_release_buffer(&status_code, &status_string);

  return major_status + ", " + minor_status;
}

void LoginMessage::authenticate() {
  if (sspi_.length() == 0) {
    ENVOY_LOG(info, "No SSPI token to authenticate");
    return;
  }

  OM_uint32 major_status, minor_status;
  // authenticate token
  /* Accept the security context */
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_ctx_id_t server_context = GSS_C_NO_CONTEXT;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_buffer_desc client_name_buffer = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc authed_token = GSS_C_EMPTY_BUFFER;

  Buffer::OwnedImpl sspi;
  sspi.add(sspi_);

  input_token.value = sspi.linearize(input_token.length);
  input_token.length = sspi.length();

#if 0 // load keytab from a file
  gss_name_t server_name = GSS_C_NO_NAME;
  gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
  const char* service_name = "MSSQLSvc/jparkdev.database.windows.net:1433@PARKJIYOUNG.COM";
  char service_name_buffer[1024];

  strncpy(service_name_buffer, service_name, sizeof(service_name_buffer));

  gss_buffer_desc name_buffer;
  name_buffer.value = static_cast<void*>(service_name_buffer);
  name_buffer.length = strlen(service_name);
  major_status =
      gss_import_name(&minor_status, &name_buffer, GSS_C_NT_HOSTBASED_SERVICE, &server_name);
  if (GSS_ERROR(major_status)) {
    ENVOY_LOG(error, "Failed to import service principal name. {}",
              format_error(major_status, minor_status));
    return;
  }

  // Acquire credentials for the service principal
  major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                  GSS_C_ACCEPT, &server_creds, NULL, NULL);
  if (GSS_ERROR(major_status)) {
    ENVOY_LOG(error, "Failed to acquire credentials for the service principal. {}",
              format_error(major_status, minor_status));
    gss_release_name(&minor_status, &server_name);
    return;
  }
#endif

  major_status = gss_accept_sec_context(&minor_status,             // Minor status
                                        &server_context,           // Security context
                                        GSS_C_NO_CREDENTIAL,       // Default server credentials
                                        &input_token,              // Input token from client
                                        GSS_C_NO_CHANNEL_BINDINGS, // No channel bindings
                                        &client_name,              // Client name
                                        NULL,                      // Mechanism OID
                                        &authed_token, // Output token to send back to the client
                                        NULL,          // Flags
                                        NULL,          // Time until expiration
                                        NULL           // Delegated credentials (optional)
  );

  if (major_status != GSS_S_COMPLETE && major_status != GSS_S_CONTINUE_NEEDED) {
    ENVOY_LOG(error, "Failed to accept security context, major_status={}, minor_status={}, {}",
              static_cast<uint16_t>(major_status), static_cast<uint16_t>(minor_status),
              format_error(major_status, minor_status));
    return;
  }

  /* Display client principal name */
  if (client_name != GSS_C_NO_NAME) {
    major_status = gss_display_name(&minor_status, client_name, &client_name_buffer, NULL);
    if (major_status == GSS_S_COMPLETE) {
      username_ =
          std::string(static_cast<char*>(client_name_buffer.value), client_name_buffer.length);
      ENVOY_LOG(info, "Authenticated client: {}", username_);
    } else {
      ENVOY_LOG(error, "Failed to display client name, major_status={}, minor_status={}",
                static_cast<uint16_t>(major_status), static_cast<uint16_t>(minor_status));
    }
    gss_release_buffer(&minor_status, &client_name_buffer);
    gss_release_name(&minor_status, &client_name);
  }

  gss_delete_sec_context(&minor_status, &server_context, GSS_C_NO_BUFFER);
  // do not release buffer since it is owned by sspi
  // TODO: check this does not leak memory
  // gss_release_buffer(&minor_status, &input_token);

  return;
}

#if 0
/* Function to display GSSAPI error messages */
void display_error(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
    OM_uint32 msg_ctx = 0;
    OM_uint32 status_code;
    gss_buffer_desc status_string;

    fprintf(stderr, "%s\n", msg);

    do
    {
        gss_display_status(&status_code, maj_stat, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &status_string);
        fprintf(stderr, "  Major Status: %s\n", (char *)status_string.value);
        gss_release_buffer(&status_code, &status_string);

        gss_display_status(&status_code, min_stat, GSS_C_MECH_CODE, GSS_C_NO_OID, &msg_ctx, &status_string);
        fprintf(stderr, "  Minor Status: %s\n", (char *)status_string.value);
        gss_release_buffer(&status_code, &status_string);
    } while (msg_ctx != 0);
}

// main codebase
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <service_principal>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *service_principal = argv[1];

    OM_uint32 major_status, minor_status;
    // make token
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;

    /* Convert the service principal to a GSSAPI name */
    gss_buffer_desc name_buffer;
    name_buffer.value = (void *)service_principal;
    name_buffer.length = strlen(service_principal);

    major_status = gss_import_name(
        &minor_status,
        &name_buffer,
        GSS_C_NT_HOSTBASED_SERVICE,
        &target_name);
    if (major_status != GSS_S_COMPLETE)
    {
        display_error(
            "Failed to import service principal",
            major_status, minor_status);
        return EXIT_FAILURE;
    }

    /* Initialize the security context */
    major_status = gss_init_sec_context(
        &minor_status,                         // Minor status
        GSS_C_NO_CREDENTIAL,                   // Default credential (use ticket cache)
        &context,                              // Security context
        target_name,                           // Target name
        GSS_C_NO_OID,                          // Mechanism (Kerberos is default)
        GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG, // Request mutual authentication and replay protection
        0,                                     // Default time limit
        GSS_C_NO_CHANNEL_BINDINGS,             // No channel bindings
        &input_token,                          // Input token (empty for first call)
        NULL,                                  // Mechanism OID
        &output_token,                         // Output token
        NULL,                                  // Flags
        NULL                                   // Time until expiration
    );

    if (major_status != GSS_S_COMPLETE && major_status != GSS_S_CONTINUE_NEEDED)
    {
        display_error("Failed to initialize security context", major_status, minor_status);
        gss_release_name(&minor_status, &target_name);
        return EXIT_FAILURE;
    }

    /* If there's an output token, send it to the server (this is just an example) */
    if (output_token.length > 0)
    {
        printf("Output token (send to server). len: %zu\n", output_token.length);
        // fwrite(output_token.value, 1, output_token.length, stdout);
        // printf("\n");

        // authenticate token
        /* Accept the security context */
        gss_ctx_id_t server_context = GSS_C_NO_CONTEXT;
        gss_name_t client_name = GSS_C_NO_NAME;
        gss_buffer_desc client_name_buffer = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc authed_token = GSS_C_EMPTY_BUFFER;

        major_status = gss_accept_sec_context(
            &minor_status,             // Minor status
            &server_context,           // Security context
            GSS_C_NO_CREDENTIAL,       // Default server credentials
            &output_token,             // Input token from client
            GSS_C_NO_CHANNEL_BINDINGS, // No channel bindings
            &client_name,              // Client name
            NULL,                      // Mechanism OID
            &authed_token,             // Output token to send back to the client
            NULL,                      // Flags
            NULL,                      // Time until expiration
            NULL                       // Delegated credentials (optional)
        );

        if (major_status != GSS_S_COMPLETE && major_status != GSS_S_CONTINUE_NEEDED)
        {
            display_error("Failed to accept security context", major_status, minor_status);
            return EXIT_FAILURE;
        }

        /* Display client principal name */
        if (client_name != GSS_C_NO_NAME)
        {
            major_status = gss_display_name(&minor_status, client_name, &client_name_buffer, NULL);
            if (major_status == GSS_S_COMPLETE)
            {
                printf("Authenticated client: %.*s\n", (int)client_name_buffer.length, (char *)client_name_buffer.value);
            }
            else
            {
                display_error("Failed to display client name", major_status, minor_status);
            }
            gss_release_buffer(&minor_status, &client_name_buffer);
            gss_release_name(&minor_status, &client_name);
        }

        /* Send output token back to client if needed */
        if (authed_token.length > 0)
        {
            printf("Output token to send to client. len: %zu\n", authed_token.length);
            // fwrite(authed_token.value, 1, authed_token.length, stdout);
            // printf("\n");
            gss_buffer_desc final_token = GSS_C_EMPTY_BUFFER;

            major_status = gss_init_sec_context(
                &minor_status,                         // Minor status
                GSS_C_NO_CREDENTIAL,                   // Default credential (use ticket cache)
                &context,                              // Security context
                target_name,                           // Target name
                GSS_C_NO_OID,                          // Mechanism (Kerberos is default)
                GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG, // Request mutual authentication and replay protection
                0,                                     // Default time limit
                GSS_C_NO_CHANNEL_BINDINGS,             // No channel bindings
                &authed_token,                         // Input token (empty for first call)
                NULL,                                  // Mechanism OID
                &final_token,                          // Output token
                NULL,                                  // Flags
                NULL                                   // Time until expiration
            );

            if (major_status != GSS_S_COMPLETE && major_status != GSS_S_CONTINUE_NEEDED)
            {
                display_error("Failed to initialize security context", major_status, minor_status);
                gss_release_name(&minor_status, &target_name);
                return EXIT_FAILURE;
            }
            else
            {
                printf("Authenticated server\n");
                printf("Final token. len: %zu\n", final_token.length);
                fwrite(final_token.value, 1, final_token.length, stdout);
                printf("\n");
            }

            gss_release_buffer(&minor_status, &authed_token);
        }

        gss_delete_sec_context(&minor_status, &server_context, GSS_C_NO_BUFFER);
        gss_release_buffer(&minor_status, &output_token);
    }

    /* Cleanup */
    gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
    gss_release_name(&minor_status, &target_name);

    printf("Kerberos authentication completed successfully.\n");
    return EXIT_SUCCESS;
}
#endif

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy