# This is a CMake file for Gmail API v1
# using the Google APIs Client Library for C++.
#
# See http://google.github.io/google-api-cpp-client/latest/start/get_started
# for more information about what to do with this file.

project (google_gmail_api)

# These sources assume that the CMakeLists.txt in ../.. added itself to
# the include directories so that include paths are specified explicitly
# with the directory #include "google/gmail_api/..."
add_library(google_gmail_api STATIC
            auto_forwarding.cc
            batch_delete_messages_request.cc
            draft.cc
            filter.cc
            filter_action.cc
            filter_criteria.cc
            forwarding_address.cc
            history.cc
            history_label_added.cc
            history_label_removed.cc
            history_message_added.cc
            history_message_deleted.cc
            imap_settings.cc
            label.cc
            list_drafts_response.cc
            list_filters_response.cc
            list_forwarding_addresses_response.cc
            list_history_response.cc
            list_labels_response.cc
            list_messages_response.cc
            list_send_as_response.cc
            list_threads_response.cc
            message.cc
            message_part.cc
            message_part_body.cc
            message_part_header.cc
            modify_message_request.cc
            modify_thread_request.cc
            pop_settings.cc
            profile.cc
            send_as.cc
            smtp_msa.cc
            thread.cc
            vacation_settings.cc
            watch_request.cc
            watch_response.cc
            gmail_service.cc)
target_link_libraries(google_gmail_api googleapis_http)
target_link_libraries(google_gmail_api googleapis_internal)
target_link_libraries(google_gmail_api googleapis_jsoncpp)
target_link_libraries(google_gmail_api googleapis_utils)
