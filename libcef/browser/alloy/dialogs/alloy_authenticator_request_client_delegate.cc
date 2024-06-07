// Copyright (c) 2019 The Chromium Embedded Framework Authors. All rights
// reserved. Use of this source code is governed by a BSD-style license that can
// be found in the LICENSE file.

#include "include/cef_authenticator_request_callback.h"

#include "libcef/browser/alloy/dialogs/alloy_authenticator_request_client_delegate.h"

#include "libcef/browser/browser_host_base.h"
#include "libcef/browser/net_service/browser_urlrequest_impl.h"
#include "libcef/browser/thread_util.h"

#include "base/memory/scoped_refptr.h"
#include "base/task/sequenced_task_runner.h"
#include "content/public/browser/global_request_id.h"
#include "content/public/browser/web_contents.h"
#include "device/fido/pin.h"

cef_authenticator_failure_reason_t GetCefAuthenticatorFailureReason(
    content::AuthenticatorRequestClientDelegate::InterestingFailureReason
        reason) {
  switch (reason) {
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kTimeout:
      return CEF_AUTHENTICATOR_FAILURE_REASON_TIMEOUT;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kKeyNotRegistered:
      return CEF_AUTHENTICATOR_FAILURE_REASON_KEY_NOT_REGISTERED;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kKeyAlreadyRegistered:
      return CEF_AUTHENTICATOR_FAILURE_REASON_KEY_ALREADY_REGISTERED;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kSoftPINBlock:
      return CEF_AUTHENTICATOR_FAILURE_REASON_SOFT_PIN_BLOCK;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kHardPINBlock:
      return CEF_AUTHENTICATOR_FAILURE_REASON_HARD_PIN_BLOCK;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kAuthenticatorRemovedDuringPINEntry:
      return CEF_AUTHENTICATOR_FAILURE_REASON_AUTHENTICATOR_REMOVED_DURING_PIN_ENTRY;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kAuthenticatorMissingResidentKeys:
      return CEF_AUTHENTICATOR_FAILURE_REASON_AUTHENTICATOR_MISSING_RESIDENT_KEYS;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kAuthenticatorMissingUserVerification:
      return CEF_AUTHENTICATOR_FAILURE_REASON_AUTHENTICATOR_MISSING_USER_VERIFICATION;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kAuthenticatorMissingLargeBlob:
      return CEF_AUTHENTICATOR_FAILURE_REASON_AUTHENTICATOR_MISSING_LARGE_BLOB;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kNoCommonAlgorithms:
      return CEF_AUTHENTICATOR_FAILURE_REASON_NO_COMMON_ALGORITHMS;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kStorageFull:
      return CEF_AUTHENTICATOR_FAILURE_REASON_STORAGE_FULL;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kUserConsentDenied:
      return CEF_AUTHENTICATOR_FAILURE_REASON_USER_CONSENT_DENIED;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kWinUserCancelled:
      return CEF_AUTHENTICATOR_FAILURE_REASON_WIN_USER_CANCELLED;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kHybridTransportError:
      return CEF_AUTHENTICATOR_FAILURE_REASON_HYBRID_TRANSPORT_ERROR;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kNoPasskeys:
      return CEF_AUTHENTICATOR_FAILURE_REASON_NO_PASSKEYS;
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kEnclaveError:
      return CEF_AUTHENTICATOR_FAILURE_REASON_NO_PASSKEYS; // simplification
    case content::AuthenticatorRequestClientDelegate::InterestingFailureReason::
        kEnclaveCancel:
      return CEF_AUTHENTICATOR_FAILURE_REASON_NO_PASSKEYS; // simplification
  }

  DCHECK(false);
  return CEF_AUTHENTICATOR_FAILURE_REASON_TIMEOUT;
}

AlloyAuthenticatorRequestClientDelegate::
    AlloyAuthenticatorRequestClientDelegate(
        content::RenderFrameHost* render_frame_host)
    : render_frame_host_(render_frame_host), weak_ptr_factory_(this) {}

AlloyAuthenticatorRequestClientDelegate::
    ~AlloyAuthenticatorRequestClientDelegate() {
  if (cancel_callback_) {
    // If the cancel callback was invoked, there's nothing left to do here.
    // But if it wasn't, this might actually be a timeout failure.
    // If either DoesBlockRequestOnFailure or OnTransactionSuccessful has
    // already been called to signal the end of an authentication, the internal
    // delegate will be destroyed already. If it isn't, the user apparently has
    // not confirmed the authentication physically on the authenticator (which
    // should result in a timeout error, but doesn't currently as of Chromium
    // 119 - the DoesBlockRequestOnFailure call with kTimeout is just done if
    // the PIN input has not yet been successfully provided) but the process has
    // ended nevertheless, as signaled by the destruction of the ClientDelegate.
    // Since the timeout situation appears to be the only one in which this
    // event flow occurs (and a cancellation through the cancel callback, but we
    // filtered that out already), we just produce a timeout error towards the
    // CEF API (so an implementor can rely on getting either a success or
    // failure response in all situations).
    if (delegate_) {
      delegate_->OnFailure(CEF_AUTHENTICATOR_FAILURE_REASON_TIMEOUT);
      delegate_ = nullptr;
    }
  }
}

bool AlloyAuthenticatorRequestClientDelegate::DoesBlockRequestOnFailure(
    InterestingFailureReason reason) {
  if (delegate_) {
    delegate_->OnFailure(GetCefAuthenticatorFailureReason(reason));
    delegate_ = nullptr;
  }
  return false;
}

void AlloyAuthenticatorRequestClientDelegate::OnTransactionSuccessful(
    RequestSource request_source,
    device::FidoRequestType request_type,
    device::AuthenticatorType authenticator_type) {
  if (delegate_) {
    delegate_->OnSuccess();
    delegate_ = nullptr;
  }
}

void AlloyAuthenticatorRequestClientDelegate::RegisterActionCallbacks(
    base::OnceClosure cancel_callback,
    base::RepeatingClosure start_over_callback,
    AccountPreselectedCallback account_preselected_callback,
    device::FidoRequestHandlerBase::RequestCallback request_callback,
    base::RepeatingClosure bluetooth_adapter_power_on_callback) {
  cancel_callback_ = std::move(cancel_callback);
}

bool AlloyAuthenticatorRequestClientDelegate::SupportsPIN() const {
  CefRefPtr<CefBrowserHostBase> browser;
  browser = CefBrowserHostBase::GetBrowserForHost(render_frame_host_);
  if (browser) {
    CefRefPtr<CefClient> client = browser->GetClient();
    if (client) {
      CefRefPtr<CefRequestHandler> handler = client->GetRequestHandler();
      if (handler) {
        bool supported = handler->GetAuthenticatorPinSupported(browser);
        if (supported) {
          return true;
        }
      }
    }
  }

  return false;
}

void AlloyAuthenticatorRequestClientDelegate::CollectPIN(
    CollectPINOptions options,
    base::OnceCallback<void(std::u16string)> provide_pin_cb) {
  base::OnceClosure cancel_cb =
      base::BindOnce(&AlloyAuthenticatorRequestClientDelegate::Cancel,
                     weak_ptr_factory_.GetWeakPtr());

  delegate_ = new AuthenticatorPinRequestDelegate(render_frame_host_, options,
                                                  std::move(provide_pin_cb),
                                                  std::move(cancel_cb));
}

void AlloyAuthenticatorRequestClientDelegate::FinishCollectToken() {
  if (delegate_) {
    delegate_->OnFinishCollectToken();
  }
}

void AlloyAuthenticatorRequestClientDelegate::Cancel() {
  if (cancel_callback_) {
    std::move(cancel_callback_).Run();
  }
}

namespace {

class AuthenticatorRequestCallbackImpl
    : public CefAuthenticatorRequestCallback {
 public:
  explicit AuthenticatorRequestCallbackImpl(
      base::WeakPtr<AuthenticatorPinRequestDelegate> delegate)
      : delegate_(delegate),
        task_runner_(base::SequencedTaskRunner::GetCurrentDefault()) {}

  AuthenticatorRequestCallbackImpl(const AuthenticatorRequestCallbackImpl&) =
      delete;
  AuthenticatorRequestCallbackImpl& operator=(
      const AuthenticatorRequestCallbackImpl&) = delete;

  ~AuthenticatorRequestCallbackImpl() override {
    if (delegate_.MaybeValid()) {
      // If |delegate_| isn't valid this will be a no-op.
      task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&AuthenticatorPinRequestDelegate::Cancel, delegate_));
    }
  }

  void Continue(const CefString& pin) override {
    if (!task_runner_->RunsTasksInCurrentSequence()) {
      task_runner_->PostTask(
          FROM_HERE, base::BindOnce(&AuthenticatorRequestCallbackImpl::Continue,
                                    this, pin));
      return;
    }

    if (delegate_) {
      delegate_->Continue(pin);
      delegate_ = nullptr;
    }
  }

  void Cancel() override {
    if (!task_runner_->RunsTasksInCurrentSequence()) {
      task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&AuthenticatorRequestCallbackImpl::Cancel, this));
      return;
    }

    if (delegate_) {
      delegate_->Cancel();
      delegate_ = nullptr;
    }
  }

 private:
  base::WeakPtr<AuthenticatorPinRequestDelegate> delegate_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  IMPLEMENT_REFCOUNTING(AuthenticatorRequestCallbackImpl);
};

cef_pin_entry_reason_t GetCefPinEntryReason(
    device::pin::PINEntryReason reason) {
  switch (reason) {
    case device::pin::PINEntryReason::kSet:
      return CEF_PIN_ENTRY_REASON_SET;
    case device::pin::PINEntryReason::kChange:
      return CEF_PIN_ENTRY_REASON_CHANGE;
    case device::pin::PINEntryReason::kChallenge:
      return CEF_PIN_ENTRY_REASON_CHALLENGE;
  }

  DCHECK(false);
  return CEF_PIN_ENTRY_REASON_CHALLENGE;
}

cef_pin_entry_error_t GetCefPinEntryError(device::pin::PINEntryError reason) {
  switch (reason) {
    case device::pin::PINEntryError::kNoError:
      return CEF_PIN_ENTRY_ERROR_NO_ERROR;
    case device::pin::PINEntryError::kInternalUvLocked:
      return CEF_PIN_ENTRY_ERROR_INTERNAL_UV_LOCKED;
    case device::pin::PINEntryError::kWrongPIN:
      return CEF_PIN_ENTRY_ERROR_WRONG_PIN;
    case device::pin::PINEntryError::kTooShort:
      return CEF_PIN_ENTRY_ERROR_TOO_SHORT;
    case device::pin::PINEntryError::kInvalidCharacters:
      return CEF_PIN_ENTRY_ERROR_INVALID_CHARACTERS;
    case device::pin::PINEntryError::kSameAsCurrentPIN:
      return CEF_PIN_ENTRY_ERROR_SAME_AS_CURRENT_PIN;
  }

  DCHECK(false);
  return CEF_PIN_ENTRY_ERROR_NO_ERROR;
}

AuthenticatorPinRequestDelegate::AuthenticatorPinRequestDelegate(
    content::RenderFrameHost* render_frame_host,
    device::FidoRequestHandlerBase::Observer::CollectPINOptions options,
    base::OnceCallback<void(std::u16string)> callback,
    base::OnceClosure cancel_callback)
    : options_(options),
      callback_(std::move(callback)),
      cancel_callback_(std::move(cancel_callback)),
      weak_ptr_factory_(this) {
  CEF_REQUIRE_UIT();

  CefRefPtr<CefBrowserHostBase> browser;
  browser = CefBrowserHostBase::GetBrowserForHost(render_frame_host);

  CefCollectPinOptions cefOptions;
  cefOptions.reason = GetCefPinEntryReason(options.reason);
  cefOptions.error = GetCefPinEntryError(options.error);
  cefOptions.min_pin_length = options.min_pin_length;
  cefOptions.attempts = options.attempts;

  // |callback| needs to be executed asynchronously.
  CEF_POST_TASK(CEF_UIT, base::BindOnce(&AuthenticatorPinRequestDelegate::Start,
                                        weak_ptr_factory_.GetWeakPtr(), browser,
                                        cefOptions));
}

void AuthenticatorPinRequestDelegate::Continue(const CefString& pin) {
  CEF_REQUIRE_UIT();
  if (!callback_.is_null()) {
    std::move(callback_).Run(pin.ToString16());
  }
}

void AuthenticatorPinRequestDelegate::Cancel() {
  CEF_REQUIRE_UIT();
  if (!cancel_callback_.is_null()) {
    std::move(cancel_callback_).Run();
  }
}

void AuthenticatorPinRequestDelegate::OnSuccess() {
  CEF_REQUIRE_UIT();
  if (result_handler_) {
    result_handler_->OnSuccess();
    result_handler_ = nullptr;
  }
}

void AuthenticatorPinRequestDelegate::OnFailure(
    const cef_authenticator_failure_reason_t reason) {
  CEF_REQUIRE_UIT();
  if (result_handler_) {
    result_handler_->OnFailure(reason);
    result_handler_ = nullptr;
  }
}

void AuthenticatorPinRequestDelegate::OnFinishCollectToken() {
  CEF_REQUIRE_UIT();
  if (result_handler_) {
    result_handler_->OnFinishCollectToken();
  }
}

void AuthenticatorPinRequestDelegate::Start(
    CefRefPtr<CefBrowserHostBase> browser,
    const CefCollectPinOptions& options) {
  CEF_REQUIRE_UIT();

  if (browser) {
    // AuthenticatorRequestCallbackImpl is bound to the current thread.
    CefRefPtr<AuthenticatorRequestCallbackImpl> callbackImpl =
        new AuthenticatorRequestCallbackImpl(weak_ptr_factory_.GetWeakPtr());

    CefRefPtr<CefClient> client = browser->GetClient();
    if (client) {
      CefRefPtr<CefRequestHandler> handler = client->GetRequestHandler();
      if (handler) {
        CefRefPtr<CefAuthenticatorResultHandler> result_handler =
            handler->GetAuthenticatorPin(browser, options, callbackImpl);
        if (result_handler) {
          result_handler_ = result_handler;
        }
        return;
      }
    }

    callbackImpl->Cancel();
  } else {
    Cancel();
  }
}

}  // namespace
