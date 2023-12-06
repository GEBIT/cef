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
// $hash=d2a67b05b0b0bcbe6228155c1e7d3450f7e329bd$
//

#include "libcef_dll/ctocpp/authenticator_request_callback_ctocpp.h"
#include "libcef_dll/shutdown_checker.h"

// VIRTUAL METHODS - Body may be edited by hand.

NO_SANITIZE("cfi-icall")
void CefAuthenticatorRequestCallbackCToCpp::Continue(const CefString& pin) {
  shutdown_checker::AssertNotShutdown();

  cef_authenticator_request_callback_t* _struct = GetStruct();
  if (CEF_MEMBER_MISSING(_struct, cont)) {
    return;
  }

  // AUTO-GENERATED CONTENT - DELETE THIS COMMENT BEFORE MODIFYING

  // Unverified params: pin

  // Execute
  _struct->cont(_struct, pin.GetStruct());
}

NO_SANITIZE("cfi-icall") void CefAuthenticatorRequestCallbackCToCpp::Cancel() {
  shutdown_checker::AssertNotShutdown();

  cef_authenticator_request_callback_t* _struct = GetStruct();
  if (CEF_MEMBER_MISSING(_struct, cancel)) {
    return;
  }

  // AUTO-GENERATED CONTENT - DELETE THIS COMMENT BEFORE MODIFYING

  // Execute
  _struct->cancel(_struct);
}

// CONSTRUCTOR - Do not edit by hand.

CefAuthenticatorRequestCallbackCToCpp::CefAuthenticatorRequestCallbackCToCpp() {
}

// DESTRUCTOR - Do not edit by hand.

CefAuthenticatorRequestCallbackCToCpp::
    ~CefAuthenticatorRequestCallbackCToCpp() {
  shutdown_checker::AssertNotShutdown();
}

template <>
cef_authenticator_request_callback_t*
CefCToCppRefCounted<CefAuthenticatorRequestCallbackCToCpp,
                    CefAuthenticatorRequestCallback,
                    cef_authenticator_request_callback_t>::
    UnwrapDerived(CefWrapperType type, CefAuthenticatorRequestCallback* c) {
  DCHECK(false) << "Unexpected class type: " << type;
  return nullptr;
}

template <>
CefWrapperType
    CefCToCppRefCounted<CefAuthenticatorRequestCallbackCToCpp,
                        CefAuthenticatorRequestCallback,
                        cef_authenticator_request_callback_t>::kWrapperType =
        WT_AUTHENTICATOR_REQUEST_CALLBACK;
