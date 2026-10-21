// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libcef/browser/ui_compositor_access_mac.h"

#include "content/browser/renderer_host/render_widget_host_view_base.h"
#include "content/browser/renderer_host/render_widget_host_view_mac.h"

UiCompositorAccessMac::UiCompositorAccessMac() {}
UiCompositorAccessMac::~UiCompositorAccessMac() = default;

ui::Compositor* UiCompositorAccessMac::ExtractCompositor(content::RenderWidgetHostView* view) {
  if (!view)
    return nullptr;

  content::RenderWidgetHostViewBase* base_view =
      static_cast<content::RenderWidgetHostViewBase*>(view);

  if (base_view->IsRenderWidgetHostViewChildFrame()) {
    base_view = base_view->GetRootView();
    if (!base_view)
      return nullptr;
  }

  content::RenderWidgetHostViewMac* mac_view =
      static_cast<content::RenderWidgetHostViewMac*>(base_view);
  if (mac_view->BrowserCompositor())
    return mac_view->BrowserCompositor()->GetCompositor();

  return nullptr;
}
