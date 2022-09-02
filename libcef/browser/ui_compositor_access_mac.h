// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCEF_BROWSER_UI_COMPOSITOR_ACCESS_MAC_H_
#define LIBCEF_BROWSER_UI_COMPOSITOR_ACCESS_MAC_H_

#include "content/public/browser/render_widget_host_view.h"
#include "ui/compositor/compositor.h"


class UiCompositorAccessMac {
 public:
  UiCompositorAccessMac();
  ~UiCompositorAccessMac();
  
  ui::Compositor* ExtractCompositor(content::RenderWidgetHostView* view);

};

#endif  // LIBCEF_BROWSER_UI_COMPOSITOR_ACCESS_MAC_H_
