// Copyright 2020 The Chromium Embedded Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libcef/browser/chrome/chrome_browser_host_impl.h"

#include "libcef/browser/browser_platform_delegate.h"
#include "libcef/browser/chrome/browser_platform_delegate_chrome.h"
#include "libcef/browser/thread_util.h"
#include "libcef/features/runtime_checks.h"

#include "base/logging.h"
#include "base/notreached.h"
#include "chrome/browser/printing/print_view_manager_common.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_commands.h"
#include "chrome/browser/ui/browser_navigator.h"
#include "chrome/browser/ui/browser_tabstrip.h"
#include "chrome/browser/ui/browser_window.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/common/pref_names.h"
#include "url/url_constants.h"

// static
CefRefPtr<ChromeBrowserHostImpl> ChromeBrowserHostImpl::Create(
    const CefBrowserCreateParams& params) {
  // Get or create the request context and profile.
  CefRefPtr<CefRequestContextImpl> request_context_impl =
      CefRequestContextImpl::GetOrCreateForRequestContext(
          params.request_context);
  CHECK(request_context_impl);
  auto cef_browser_context = request_context_impl->GetBrowserContext();
  CHECK(cef_browser_context);
  auto profile = cef_browser_context->AsProfile();

  Browser::CreateParams chrome_params =
      Browser::CreateParams(profile, /*user_gesture=*/false);

  // Pass |params| to cef::BrowserDelegate::Create from the Browser constructor.
  chrome_params.cef_params = base::MakeRefCounted<DelegateCreateParams>(params);

  // Create the Browser. This will indirectly create the ChomeBrowserDelegate.
  // The same params will be used to create a new Browser if the tab is dragged
  // out of the existing Browser.
  auto browser = new Browser(chrome_params);

  GURL url = params.url;
  if (url.is_empty()) {
    // Chrome will navigate to kChromeUINewTabURL by default. We want to keep
    // the current CEF behavior of not navigating at all. Use a special URL that
    // will be recognized in HandleNonNavigationAboutURL.
    url = GURL("chrome://ignore/");
  }

  // Add a new tab. This will indirectly create a new tab WebContents and
  // call ChromeBrowserDelegate::OnWebContentsCreated to create the associated
  // ChromeBrowserHostImpl.
  chrome::AddTabAt(browser, url, /*idx=*/-1, /*foreground=*/true);

  // The new tab WebContents.
  auto web_contents = browser->tab_strip_model()->GetActiveWebContents();
  CHECK(web_contents);

  // The associated ChromeBrowserHostImpl.
  auto browser_host =
      ChromeBrowserHostImpl::GetBrowserForContents(web_contents);
  CHECK(browser_host);

  browser->window()->Show();

  return browser_host;
}

// static
CefRefPtr<ChromeBrowserHostImpl> ChromeBrowserHostImpl::GetBrowserForHost(
    const content::RenderViewHost* host) {
  REQUIRE_CHROME_RUNTIME();
  auto browser = CefBrowserHostBase::GetBrowserForHost(host);
  return static_cast<ChromeBrowserHostImpl*>(browser.get());
}

// static
CefRefPtr<ChromeBrowserHostImpl> ChromeBrowserHostImpl::GetBrowserForHost(
    const content::RenderFrameHost* host) {
  REQUIRE_CHROME_RUNTIME();
  auto browser = CefBrowserHostBase::GetBrowserForHost(host);
  return static_cast<ChromeBrowserHostImpl*>(browser.get());
}

// static
CefRefPtr<ChromeBrowserHostImpl> ChromeBrowserHostImpl::GetBrowserForContents(
    const content::WebContents* contents) {
  REQUIRE_CHROME_RUNTIME();
  auto browser = CefBrowserHostBase::GetBrowserForContents(contents);
  return static_cast<ChromeBrowserHostImpl*>(browser.get());
}

// static
CefRefPtr<ChromeBrowserHostImpl>
ChromeBrowserHostImpl::GetBrowserForFrameTreeNode(int frame_tree_node_id) {
  REQUIRE_CHROME_RUNTIME();
  auto browser =
      CefBrowserHostBase::GetBrowserForFrameTreeNode(frame_tree_node_id);
  return static_cast<ChromeBrowserHostImpl*>(browser.get());
}

// static
CefRefPtr<ChromeBrowserHostImpl> ChromeBrowserHostImpl::GetBrowserForFrameRoute(
    int render_process_id,
    int render_routing_id) {
  REQUIRE_CHROME_RUNTIME();
  auto browser = CefBrowserHostBase::GetBrowserForFrameRoute(render_process_id,
                                                             render_routing_id);
  return static_cast<ChromeBrowserHostImpl*>(browser.get());
}

ChromeBrowserHostImpl::~ChromeBrowserHostImpl() = default;

void ChromeBrowserHostImpl::OnWebContentsDestroyed(
    content::WebContents* web_contents) {
  platform_delegate_->WebContentsDestroyed(web_contents);
  DestroyBrowser();
}

void ChromeBrowserHostImpl::OnSetFocus(cef_focus_source_t source) {
  if (!CEF_CURRENTLY_ON_UIT()) {
    CEF_POST_TASK(CEF_UIT, base::BindOnce(&ChromeBrowserHostImpl::OnSetFocus,
                                          this, source));
    return;
  }

  if (contents_delegate_->OnSetFocus(source))
    return;

  if (browser_) {
    const int tab_index = GetCurrentTabIndex();
    if (tab_index != TabStripModel::kNoTab) {
      chrome::SelectNumberedTab(browser_, tab_index);
    }
  }
}

void ChromeBrowserHostImpl::CloseBrowser(bool force_close) {
  // Always do this asynchronously because TabStripModel is not re-entrant.
  CEF_POST_TASK(CEF_UIT, base::BindOnce(&ChromeBrowserHostImpl::DoCloseBrowser,
                                        this, force_close));
}

bool ChromeBrowserHostImpl::TryCloseBrowser() {
  NOTIMPLEMENTED();
  return false;
}

void ChromeBrowserHostImpl::SetFocus(bool focus) {
  if (focus) {
    OnSetFocus(FOCUS_SOURCE_SYSTEM);
  }
}

CefWindowHandle ChromeBrowserHostImpl::GetWindowHandle() {
  NOTIMPLEMENTED();
  return kNullWindowHandle;
}

CefWindowHandle ChromeBrowserHostImpl::GetOpenerWindowHandle() {
  NOTIMPLEMENTED();
  return kNullWindowHandle;
}

bool ChromeBrowserHostImpl::HasView() {
  // TODO(chrome-runtime): Support Views-hosted browsers.
  return false;
}

double ChromeBrowserHostImpl::GetZoomLevel() {
  NOTIMPLEMENTED();
  return 0.0;
}

void ChromeBrowserHostImpl::SetZoomLevel(double zoomLevel) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::RunFileDialog(
    FileDialogMode mode,
    const CefString& title,
    const CefString& default_file_path,
    const std::vector<CefString>& accept_filters,
    int selected_accept_filter,
    CefRefPtr<CefRunFileDialogCallback> callback) {
  NOTIMPLEMENTED();
  callback->OnFileDialogDismissed(0, {});
}

void ChromeBrowserHostImpl::Print() {
  if (!CEF_CURRENTLY_ON_UIT()) {
    CEF_POST_TASK(CEF_UIT, base::BindOnce(&ChromeBrowserHostImpl::Print, this));
    return;
  }

  if (browser_) {
    // Like chrome::Print() but specifying the WebContents.
    printing::StartPrint(GetWebContents(),
                         /*print_renderer=*/mojo::NullAssociatedRemote(),
                         browser_->profile()->GetPrefs()->GetBoolean(
                             prefs::kPrintPreviewDisabled),
                         /*has_selection=*/false);
  }
}

void ChromeBrowserHostImpl::PrintToPDF(
    const CefString& path,
    const CefPdfPrintSettings& settings,
    CefRefPtr<CefPdfPrintCallback> callback) {
  NOTIMPLEMENTED();
  callback->OnPdfPrintFinished(CefString(), false);
}

void ChromeBrowserHostImpl::Find(int identifier,
                                 const CefString& searchText,
                                 bool forward,
                                 bool matchCase,
                                 bool findNext) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::StopFinding(bool clearSelection) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::ShowDevTools(const CefWindowInfo& windowInfo,
                                         CefRefPtr<CefClient> client,
                                         const CefBrowserSettings& settings,
                                         const CefPoint& inspect_element_at) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::CloseDevTools() {
  NOTIMPLEMENTED();
}

bool ChromeBrowserHostImpl::HasDevTools() {
  NOTIMPLEMENTED();
  return false;
}

bool ChromeBrowserHostImpl::SendDevToolsMessage(const void* message,
                                                size_t message_size) {
  NOTIMPLEMENTED();
  return false;
}

int ChromeBrowserHostImpl::ExecuteDevToolsMethod(
    int message_id,
    const CefString& method,
    CefRefPtr<CefDictionaryValue> params) {
  NOTIMPLEMENTED();
  return 0;
}

CefRefPtr<CefRegistration> ChromeBrowserHostImpl::AddDevToolsMessageObserver(
    CefRefPtr<CefDevToolsMessageObserver> observer) {
  NOTIMPLEMENTED();
  return nullptr;
}

bool ChromeBrowserHostImpl::IsWindowRenderingDisabled() {
  return false;
}

void ChromeBrowserHostImpl::WasResized() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::WasHidden(bool hidden) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::NotifyScreenInfoChanged() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::Invalidate(PaintElementType type) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::SendExternalBeginFrame() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::SendTouchEvent(const CefTouchEvent& event) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::SendFocusEvent(bool setFocus) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::SendCaptureLostEvent() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::NotifyMoveOrResizeStarted() {
  NOTIMPLEMENTED();
}

int ChromeBrowserHostImpl::GetWindowlessFrameRate() {
  return 0;
}

void ChromeBrowserHostImpl::SetWindowlessFrameRate(int frame_rate) {}

void ChromeBrowserHostImpl::ImeSetComposition(
    const CefString& text,
    const std::vector<CefCompositionUnderline>& underlines,
    const CefRange& replacement_range,
    const CefRange& selection_range) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::ImeCommitText(const CefString& text,
                                          const CefRange& replacement_range,
                                          int relative_cursor_pos) {
  NOTIMPLEMENTED();
}
void ChromeBrowserHostImpl::ImeFinishComposingText(bool keep_selection) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::ImeCancelComposition() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::DragTargetDragEnter(
    CefRefPtr<CefDragData> drag_data,
    const CefMouseEvent& event,
    DragOperationsMask allowed_ops) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::DragTargetDragOver(const CefMouseEvent& event,
                                               DragOperationsMask allowed_ops) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::DragTargetDragLeave() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::DragTargetDrop(const CefMouseEvent& event) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::DragSourceSystemDragEnded() {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::DragSourceEndedAt(int x,
                                              int y,
                                              DragOperationsMask op) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::SetAudioMuted(bool mute) {
  NOTIMPLEMENTED();
}

bool ChromeBrowserHostImpl::IsAudioMuted() {
  NOTIMPLEMENTED();
  return false;
}

void ChromeBrowserHostImpl::SetAccessibilityState(
    cef_state_t accessibility_state) {
  NOTIMPLEMENTED();
}

void ChromeBrowserHostImpl::SetAutoResizeEnabled(bool enabled,
                                                 const CefSize& min_size,
                                                 const CefSize& max_size) {
  NOTIMPLEMENTED();
}

CefRefPtr<CefExtension> ChromeBrowserHostImpl::GetExtension() {
  return nullptr;
}

bool ChromeBrowserHostImpl::IsBackgroundHost() {
  return false;
}

bool ChromeBrowserHostImpl::Navigate(const content::OpenURLParams& params) {
  CEF_REQUIRE_UIT();
  if (GetCurrentTabIndex() == TabStripModel::kNoTab) {
    // We can't navigate via the Browser because we don't have a current tab.
    return CefBrowserHostBase::Navigate(params);
  }

  if (browser_) {
    // This is generally equivalent to calling Browser::OpenURL, except:
    // 1. It doesn't trigger a call to CefRequestHandler::OnOpenURLFromTab, and
    // 2. It navigates in this CefBrowserHost's WebContents instead of
    //    (a) creating a new WebContents, or (b) using the Browser's active
    //    WebContents (which may not be the same), and
    // 3. There is no risk of triggering chrome's popup blocker.
    NavigateParams nav_params(browser_, params.url, params.transition);
    nav_params.FillNavigateParamsFromOpenURLParams(params);

    // Always navigate in the current tab.
    nav_params.disposition = WindowOpenDisposition::CURRENT_TAB;
    nav_params.source_contents = GetWebContents();

    nav_params.tabstrip_add_types = TabStripModel::ADD_NONE;
    if (params.user_gesture)
      nav_params.window_action = NavigateParams::SHOW_WINDOW;
    ::Navigate(&nav_params);
    return true;
  }
  return false;
}

ChromeBrowserHostImpl::ChromeBrowserHostImpl(
    const CefBrowserSettings& settings,
    CefRefPtr<CefClient> client,
    std::unique_ptr<CefBrowserPlatformDelegate> platform_delegate,
    scoped_refptr<CefBrowserInfo> browser_info,
    CefRefPtr<CefRequestContextImpl> request_context)
    : CefBrowserHostBase(settings,
                         client,
                         std::move(platform_delegate),
                         browser_info,
                         request_context) {}

void ChromeBrowserHostImpl::Attach(Browser* browser,
                                   content::WebContents* web_contents) {
  DCHECK(browser);
  DCHECK(web_contents);

  platform_delegate_->WebContentsCreated(web_contents,
                                         /*own_web_contents=*/false);

  SetBrowser(browser);
  contents_delegate_->ObserveWebContents(web_contents);
  InitializeBrowser();
}

void ChromeBrowserHostImpl::SetBrowser(Browser* browser) {
  CEF_REQUIRE_UIT();
  browser_ = browser;
  static_cast<CefBrowserPlatformDelegateChrome*>(platform_delegate_.get())
      ->set_chrome_browser(browser);
}

void ChromeBrowserHostImpl::InitializeBrowser() {
  CEF_REQUIRE_UIT();
  DCHECK(browser_);

  // Associate the platform delegate with this browser.
  platform_delegate_->BrowserCreated(this);

  CefBrowserHostBase::InitializeBrowser();

  // The WebContents won't be added to the Browser's TabStripModel until later
  // in the current call stack. Block navigation until that time.
  auto navigation_lock = browser_info_->CreateNavigationLock();
  OnAfterCreated();
}

void ChromeBrowserHostImpl::DestroyBrowser() {
  CEF_REQUIRE_UIT();
  browser_ = nullptr;

  OnBeforeClose();
  OnBrowserDestroyed();

  // Disassociate the platform delegate from this browser.
  platform_delegate_->BrowserDestroyed(this);

  CefBrowserHostBase::DestroyBrowser();
}

void ChromeBrowserHostImpl::DoCloseBrowser(bool force_close) {
  CEF_REQUIRE_UIT();
  if (browser_) {
    // Like chrome::CloseTab() but specifying the WebContents.
    const int tab_index = GetCurrentTabIndex();
    if (tab_index != TabStripModel::kNoTab) {
      browser_->tab_strip_model()->CloseWebContentsAt(
          tab_index, TabStripModel::CLOSE_CREATE_HISTORICAL_TAB |
                         TabStripModel::CLOSE_USER_GESTURE);
    }
  }
}

int ChromeBrowserHostImpl::GetCurrentTabIndex() const {
  CEF_REQUIRE_UIT();
  if (browser_) {
    return browser_->tab_strip_model()->GetIndexOfWebContents(GetWebContents());
  }
  return TabStripModel::kNoTab;
}

void ChromeBrowserHostImpl::SetRenderingBlocked(bool blocked) {
  // Doing nothing; this is just a dummy method to satisfy the CefBrowser interface. 
  // Blocking rendering is not supported for the chrome impl.
}