// Copyright 2010 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This code was generated by google-apis-code-generator 1.5.1
//   Build date: 2016-07-08 17:28:43 UTC
//   on: 2016-08-08, 17:19:17 UTC
//   C++ generator version: 0.1.4

// ----------------------------------------------------------------------------
// NOTE: This file is generated from Google APIs Discovery Service.
// Service:
//   Gmail API (gmail/v1)
// Generated from:
//   Version: v1
//   Revision: 48
// Generated by:
//    Tool: google-apis-code-generator 1.5.1
//     C++: 0.1.4
#ifndef  GOOGLE_GMAIL_API_MODIFY_THREAD_REQUEST_H_
#define  GOOGLE_GMAIL_API_MODIFY_THREAD_REQUEST_H_

#include <string>
#include "googleapis/base/macros.h"
#include "googleapis/client/data/jsoncpp_data.h"
#include "googleapis/strings/stringpiece.h"

namespace Json {
class Value;
}  // namespace Json

namespace google_gmail_api {
using namespace googleapis;

/**
 * No description provided.
 *
 * @ingroup DataObject
 */
class ModifyThreadRequest : public client::JsonCppData {
 public:
  /**
   * Creates a new default instance.
   *
   * @return Ownership is passed back to the caller.
   */
  static ModifyThreadRequest* New();

  /**
   * Standard constructor for an immutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit ModifyThreadRequest(const Json::Value& storage);

  /**
   * Standard constructor for a mutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit ModifyThreadRequest(Json::Value* storage);

  /**
   * Standard destructor.
   */
  virtual ~ModifyThreadRequest();

  /**
   * Returns a string denoting the type of this data object.
   *
   * @return <code>google_gmail_api::ModifyThreadRequest</code>
   */
  const StringPiece GetTypeName() const {
    return StringPiece("google_gmail_api::ModifyThreadRequest");
  }

  /**
   * Determine if the '<code>addLabelIds</code>' attribute was set.
   *
   * @return true if the '<code>addLabelIds</code>' attribute was set.
   */
  bool has_add_label_ids() const {
    return Storage().isMember("addLabelIds");
  }

  /**
   * Clears the '<code>addLabelIds</code>' attribute.
   */
  void clear_add_label_ids() {
    MutableStorage()->removeMember("addLabelIds");
  }


  /**
   * Get a reference to the value of the '<code>addLabelIds</code>' attribute.
   */
  const client::JsonCppArray<string > get_add_label_ids() const {
     const Json::Value& storage = Storage("addLabelIds");
    return client::JsonValueToCppValueHelper<client::JsonCppArray<string > >(storage);
  }

  /**
   * Gets a reference to a mutable value of the '<code>addLabelIds</code>'
   * property.
   *
   * A list of IDs of labels to add to this thread.
   *
   * @return The result can be modified to change the attribute value.
   */
  client::JsonCppArray<string > mutable_addLabelIds() {
    Json::Value* storage = MutableStorage("addLabelIds");
    return client::JsonValueToMutableCppValueHelper<client::JsonCppArray<string > >(storage);
  }

  /**
   * Determine if the '<code>removeLabelIds</code>' attribute was set.
   *
   * @return true if the '<code>removeLabelIds</code>' attribute was set.
   */
  bool has_remove_label_ids() const {
    return Storage().isMember("removeLabelIds");
  }

  /**
   * Clears the '<code>removeLabelIds</code>' attribute.
   */
  void clear_remove_label_ids() {
    MutableStorage()->removeMember("removeLabelIds");
  }


  /**
   * Get a reference to the value of the '<code>removeLabelIds</code>'
   * attribute.
   */
  const client::JsonCppArray<string > get_remove_label_ids() const {
     const Json::Value& storage = Storage("removeLabelIds");
    return client::JsonValueToCppValueHelper<client::JsonCppArray<string > >(storage);
  }

  /**
   * Gets a reference to a mutable value of the '<code>removeLabelIds</code>'
   * property.
   *
   * A list of IDs of labels to remove from this thread.
   *
   * @return The result can be modified to change the attribute value.
   */
  client::JsonCppArray<string > mutable_removeLabelIds() {
    Json::Value* storage = MutableStorage("removeLabelIds");
    return client::JsonValueToMutableCppValueHelper<client::JsonCppArray<string > >(storage);
  }

 private:
  void operator=(const ModifyThreadRequest&);
};  // ModifyThreadRequest
}  // namespace google_gmail_api
#endif  // GOOGLE_GMAIL_API_MODIFY_THREAD_REQUEST_H_