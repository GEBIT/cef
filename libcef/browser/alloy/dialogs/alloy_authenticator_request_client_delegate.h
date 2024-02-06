// Copyright (c) 2023 The Chromium Embedded Framework Authors. All rights
// reserved. Use of this source code is governed by a BSD-style license that can
// be found in the LICENSE file.

#ifndef CEF_LIBCEF_BROWSER_ALLOY_DIALOGS_ALLOY_AUTHENTICATOR_REQUEST_CLIENT_DELEGATE_H_
#define CEF_LIBCEF_BROWSER_ALLOY_DIALOGS_ALLOY_AUTHENTICATOR_REQUEST_CLIENT_DELEGATE_H_

#include "include/cef_authenticator_result_handler.h"
#include "include/cef_base.h"

#include "base/memory/weak_ptr.h"
#include "content/public/browser/authenticator_request_client_delegate.h"
#include "content/public/browser/content_browser_client.h"
#include "net/base/auth.h"

class CefBrowserHostBase;

namespace {

class AuthenticatorPinRequestDelegate : public virtual CefBaseRefCounted {
 public:
  // This object will be deleted when |callback| is executed or the request is
  // canceled. |callback| should not be executed after this object is deleted.
  AuthenticatorPinRequestDelegate(
      content::RenderFrameHost* render_frame_host,
      device::FidoRequestHandlerBase::Observer::CollectPINOptions options,
      base::OnceCallback<void(std::u16string)> callback,
      base::OnceClosure cancel_callback);

  void Continue(const CefString& pin);
  void Cancel();

  void OnSuccess();
  void OnFailure(const cef_authenticator_failure_reason_t reason);
  void OnFinishCollectToken();

 private:
  void Start(CefRefPtr<CefBrowserHostBase> browser,
             const CefCollectPinOptions& options);
  void ReportSuccess();
  void ReportFailure(const cef_authenticator_failure_reason_t reason);

  device::FidoRequestHandlerBase::Observer::CollectPINOptions options_;
  base::OnceCallback<void(std::u16string)> callback_;
  base::OnceClosure cancel_callback_;
  CefRefPtr<CefAuthenticatorResultHandler> result_handler_;
  base::WeakPtrFactory<AuthenticatorPinRequestDelegate> weak_ptr_factory_;

  IMPLEMENT_REFCOUNTING(AuthenticatorPinRequestDelegate);
};

}  // namespace

class AlloyAuthenticatorRequestClientDelegate
    : public content::AuthenticatorRequestClientDelegate {
 public:
  AlloyAuthenticatorRequestClientDelegate(
      content::RenderFrameHost* render_frame_host);

  ~AlloyAuthenticatorRequestClientDelegate() override;

  bool DoesBlockRequestOnFailure(InterestingFailureReason reason) override;
  void OnTransactionSuccessful(
      RequestSource request_source,
      device::FidoRequestType request_type,
      device::AuthenticatorType authenticator_type) override;
  void RegisterActionCallbacks(
      base::OnceClosure cancel_callback,
      base::RepeatingClosure start_over_callback,
      AccountPreselectedCallback account_preselected_callback,
      device::FidoRequestHandlerBase::RequestCallback request_callback,
      base::RepeatingClosure bluetooth_adapter_power_on_callback) override;
  bool SupportsPIN() const override;
  void CollectPIN(
      CollectPINOptions options,
      base::OnceCallback<void(std::u16string)> provide_pin_cb) override;
  void FinishCollectToken() override;

 private:
  void Cancel();

  base::OnceClosure cancel_callback_;
  content::RenderFrameHost* render_frame_host_;
  CefRefPtr<AuthenticatorPinRequestDelegate> delegate_;
  base::WeakPtrFactory<AlloyAuthenticatorRequestClientDelegate>
      weak_ptr_factory_;
};

#endif  // CEF_LIBCEF_BROWSER_ALLOY_DIALOGS_ALLOY_AUTHENTICATOR_REQUEST_CLIENT_DELEGATE_H_
