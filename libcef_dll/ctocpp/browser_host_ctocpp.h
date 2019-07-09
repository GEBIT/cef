// Copyright (c) 2019 The Chromium Embedded Framework Authors. All rights
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
// $hash=d9a6d69ef996bfb961d0b675fe37e5a2b23b12cc$
//

#ifndef CEF_LIBCEF_DLL_CTOCPP_BROWSER_HOST_CTOCPP_H_
#define CEF_LIBCEF_DLL_CTOCPP_BROWSER_HOST_CTOCPP_H_
#pragma once

#if !defined(WRAPPING_CEF_SHARED)
#error This file can be included wrapper-side only
#endif

#include <vector>
#include "include/capi/cef_browser_capi.h"
#include "include/capi/cef_client_capi.h"
#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "libcef_dll/ctocpp/ctocpp_ref_counted.h"

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class CefBrowserHostCToCpp : public CefCToCppRefCounted<CefBrowserHostCToCpp,
                                                        CefBrowserHost,
                                                        cef_browser_host_t> {
 public:
  CefBrowserHostCToCpp();
  virtual ~CefBrowserHostCToCpp();

  // CefBrowserHost methods.
  CefRefPtr<CefBrowser> GetBrowser() OVERRIDE;
  void CloseBrowser(bool force_close) OVERRIDE;
  bool TryCloseBrowser() OVERRIDE;
  void SetFocus(bool focus) OVERRIDE;
  CefWindowHandle GetWindowHandle() OVERRIDE;
  CefWindowHandle GetOpenerWindowHandle() OVERRIDE;
  bool HasView() OVERRIDE;
  CefRefPtr<CefClient> GetClient() OVERRIDE;
  CefRefPtr<CefRequestContext> GetRequestContext() OVERRIDE;
  double GetZoomLevel() OVERRIDE;
  void SetZoomLevel(double zoomLevel) OVERRIDE;
  void RunFileDialog(FileDialogMode mode,
                     const CefString& title,
                     const CefString& default_file_path,
                     const std::vector<CefString>& accept_filters,
                     int selected_accept_filter,
                     CefRefPtr<CefRunFileDialogCallback> callback) OVERRIDE;
  void StartDownload(const CefString& url) OVERRIDE;
  void DownloadImage(const CefString& image_url,
                     bool is_favicon,
                     uint32 max_image_size,
                     bool bypass_cache,
                     CefRefPtr<CefDownloadImageCallback> callback) OVERRIDE;
  void Print() OVERRIDE;
  void PrintToPDF(const CefString& path,
                  const CefPdfPrintSettings& settings,
                  CefRefPtr<CefPdfPrintCallback> callback) OVERRIDE;
  void Find(int identifier,
            const CefString& searchText,
            bool forward,
            bool matchCase,
            bool findNext) OVERRIDE;
  void StopFinding(bool clearSelection) OVERRIDE;
  void ShowDevTools(const CefWindowInfo& windowInfo,
                    CefRefPtr<CefClient> client,
                    const CefBrowserSettings& settings,
                    const CefPoint& inspect_element_at) OVERRIDE;
  void CloseDevTools() OVERRIDE;
  bool HasDevTools() OVERRIDE;
  void GetNavigationEntries(CefRefPtr<CefNavigationEntryVisitor> visitor,
                            bool current_only) OVERRIDE;
  void SetMouseCursorChangeDisabled(bool disabled) OVERRIDE;
  bool IsMouseCursorChangeDisabled() OVERRIDE;
  void ReplaceMisspelling(const CefString& word) OVERRIDE;
  void AddWordToDictionary(const CefString& word) OVERRIDE;
  bool IsWindowRenderingDisabled() OVERRIDE;
  void WasResized() OVERRIDE;
  void WasHidden(bool hidden) OVERRIDE;
  void SetRenderingBlocked(bool blocked) OVERRIDE;
  void NotifyScreenInfoChanged() OVERRIDE;
  void Invalidate(PaintElementType type) OVERRIDE;
  void SendExternalBeginFrame() OVERRIDE;
  void SendKeyEvent(const CefKeyEvent& event) OVERRIDE;
  void SendMouseClickEvent(const CefMouseEvent& event,
                           MouseButtonType type,
                           bool mouseUp,
                           int clickCount) OVERRIDE;
  void SendMouseMoveEvent(const CefMouseEvent& event, bool mouseLeave) OVERRIDE;
  void SendMouseWheelEvent(const CefMouseEvent& event,
                           int deltaX,
                           int deltaY) OVERRIDE;
  void SendTouchEvent(const CefTouchEvent& event) OVERRIDE;
  void SendFocusEvent(bool setFocus) OVERRIDE;
  void SendCaptureLostEvent() OVERRIDE;
  void NotifyMoveOrResizeStarted() OVERRIDE;
  int GetWindowlessFrameRate() OVERRIDE;
  void SetWindowlessFrameRate(int frame_rate) OVERRIDE;
  void ImeSetComposition(const CefString& text,
                         const std::vector<CefCompositionUnderline>& underlines,
                         const CefRange& replacement_range,
                         const CefRange& selection_range) OVERRIDE;
  void ImeCommitText(const CefString& text,
                     const CefRange& replacement_range,
                     int relative_cursor_pos) OVERRIDE;
  void ImeFinishComposingText(bool keep_selection) OVERRIDE;
  void ImeCancelComposition() OVERRIDE;
  void DragTargetDragEnter(CefRefPtr<CefDragData> drag_data,
                           const CefMouseEvent& event,
                           DragOperationsMask allowed_ops) OVERRIDE;
  void DragTargetDragOver(const CefMouseEvent& event,
                          DragOperationsMask allowed_ops) OVERRIDE;
  void DragTargetDragLeave() OVERRIDE;
  void DragTargetDrop(const CefMouseEvent& event) OVERRIDE;
  void DragSourceEndedAt(int x, int y, DragOperationsMask op) OVERRIDE;
  void DragSourceSystemDragEnded() OVERRIDE;
  CefRefPtr<CefNavigationEntry> GetVisibleNavigationEntry() OVERRIDE;
  void SetAccessibilityState(cef_state_t accessibility_state) OVERRIDE;
  void SetAutoResizeEnabled(bool enabled,
                            const CefSize& min_size,
                            const CefSize& max_size) OVERRIDE;
  CefRefPtr<CefExtension> GetExtension() OVERRIDE;
  bool IsBackgroundHost() OVERRIDE;
  void SetAudioMuted(bool mute) OVERRIDE;
  bool IsAudioMuted() OVERRIDE;
};

#endif  // CEF_LIBCEF_DLL_CTOCPP_BROWSER_HOST_CTOCPP_H_
