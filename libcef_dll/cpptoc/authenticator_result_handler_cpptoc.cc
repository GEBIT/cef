// Copyright (c) 2023 The Chromium Embedded Framework Authors. All rights
// reserved. Use of this source code is governed by a BSD-style license that
// can be found in the LICENSE file.
//
// ---------------------------------------------------------------------------
//
// This file was generated by the CEF translator tool. If making changes by
// hand only do so within the body of existing method and function
// implementations. See the translator.README.txt file in the tools directory
// for more information.
//
// $hash=69a53c98036ff0473f9da181220dc893d6b4c6e9$
//

#include "libcef_dll/cpptoc/authenticator_result_handler_cpptoc.h"

namespace {

// MEMBER FUNCTIONS - Body may be edited by hand.

void CEF_CALLBACK authenticator_result_handler_on_failure(
    struct _cef_authenticator_result_handler_t* self,
    cef_authenticator_failure_reason_t reason) {
  // AUTO-GENERATED CONTENT - DELETE THIS COMMENT BEFORE MODIFYING

  DCHECK(self);
  if (!self) {
    return;
  }

  // Execute
  CefAuthenticatorResultHandlerCppToC::Get(self)->OnFailure(reason);
}

void CEF_CALLBACK authenticator_result_handler_on_success(
    struct _cef_authenticator_result_handler_t* self) {
  // AUTO-GENERATED CONTENT - DELETE THIS COMMENT BEFORE MODIFYING

  DCHECK(self);
  if (!self) {
    return;
  }

  // Execute
  CefAuthenticatorResultHandlerCppToC::Get(self)->OnSuccess();
}

void CEF_CALLBACK authenticator_result_handler_on_finish_collect_token(
    struct _cef_authenticator_result_handler_t* self) {
  // AUTO-GENERATED CONTENT - DELETE THIS COMMENT BEFORE MODIFYING

  DCHECK(self);
  if (!self) {
    return;
  }

  // Execute
  CefAuthenticatorResultHandlerCppToC::Get(self)->OnFinishCollectToken();
}

}  // namespace

// CONSTRUCTOR - Do not edit by hand.

CefAuthenticatorResultHandlerCppToC::CefAuthenticatorResultHandlerCppToC() {
  GetStruct()->on_failure = authenticator_result_handler_on_failure;
  GetStruct()->on_success = authenticator_result_handler_on_success;
  GetStruct()->on_finish_collect_token =
      authenticator_result_handler_on_finish_collect_token;
}

// DESTRUCTOR - Do not edit by hand.

CefAuthenticatorResultHandlerCppToC::~CefAuthenticatorResultHandlerCppToC() {}

template <>
CefRefPtr<CefAuthenticatorResultHandler>
CefCppToCRefCounted<CefAuthenticatorResultHandlerCppToC,
                    CefAuthenticatorResultHandler,
                    cef_authenticator_result_handler_t>::
    UnwrapDerived(CefWrapperType type, cef_authenticator_result_handler_t* s) {
  DCHECK(false) << "Unexpected class type: " << type;
  return nullptr;
}

template <>
CefWrapperType
    CefCppToCRefCounted<CefAuthenticatorResultHandlerCppToC,
                        CefAuthenticatorResultHandler,
                        cef_authenticator_result_handler_t>::kWrapperType =
        WT_AUTHENTICATOR_RESULT_HANDLER;