# icon loading utility for svg icons

import os
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtCore import QSize, QByteArray, Qt
from typing import Optional

from binaryninjaui import getThemeColor, ThemeColor


def _get_theme_colors() -> tuple[str, str]:
    """get theme-appropriate colors for normal and disabled states"""
    try:
        # get theme-aware colors for icons
        normal_color = getThemeColor(ThemeColor.AddressColor)
        disabled_color = getThemeColor(ThemeColor.DisabledWidgetColor)
        return normal_color.name(), disabled_color.name()
    except Exception:
        pass

    # fallback colors if theme not available
    return "#CCCCCC", "#666666"


def load_icon(icon_name: str, size: int = 24) -> Optional[QIcon]:
    """
    load svg icon from the icons directory

    args:
        icon_name: name of the svg file (without .svg extension)
        size: icon size in pixels (default 24)

    returns:
        QIcon if successful, None if icon not found
    """
    try:
        # get path to icons directory (relative to this file)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(current_dir))  # go up two levels
        icon_path = os.path.join(project_root, "icons", f"{icon_name}.svg")

        if not os.path.exists(icon_path):
            print(f"warning: icon not found: {icon_path}")
            return None

        # read svg content as text to handle currentColor
        with open(icon_path, "r", encoding="utf-8") as f:
            svg_content = f.read()

        # get theme-appropriate colors
        normal_color, disabled_color = _get_theme_colors()

        # create icon with both normal and disabled states
        icon = QIcon()

        # create normal state with theme color
        normal_svg = svg_content.replace("currentColor", normal_color)
        normal_pixmap = _render_svg_content(normal_svg, size)
        if normal_pixmap:
            icon.addPixmap(normal_pixmap, QIcon.Normal)

        # create disabled state with theme color
        disabled_svg = svg_content.replace("currentColor", disabled_color)
        disabled_pixmap = _render_svg_content(disabled_svg, size)
        if disabled_pixmap:
            icon.addPixmap(disabled_pixmap, QIcon.Disabled)

        return icon if not icon.isNull() else None

    except Exception as e:
        print(f"warning: failed to load icon '{icon_name}': {e}")
        return None


def _render_svg_content(svg_content: str, size: int) -> Optional[QPixmap]:
    """
    render svg content to pixmap

    args:
        svg_content: svg content as string with colors replaced
        size: target size in pixels

    returns:
        QPixmap if successful, None on error
    """
    try:
        # convert to QByteArray for renderer
        svg_bytes = QByteArray(svg_content.encode("utf-8"))
        renderer = QSvgRenderer(svg_bytes)

        if not renderer.isValid():
            return None

        # create pixmap with proper transparent background
        pixmap = QPixmap(QSize(size, size))
        pixmap.fill(Qt.transparent)  # proper transparency

        # render svg to pixmap with high quality
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)
        renderer.render(painter)
        painter.end()

        return pixmap

    except Exception as e:
        print(f"warning: failed to render svg content: {e}")
        return None


def create_fallback_icon(text: str, size: int = 24) -> QIcon:
    """
    create a simple text-based fallback icon

    args:
        text: text to display (usually 1-2 characters)
        size: icon size in pixels (default 24)

    returns:
        QIcon with text-based icon
    """
    try:
        from PySide6.QtGui import QPainter, QFont
        from PySide6.QtCore import Qt

        pixmap = QPixmap(QSize(size, size))
        pixmap.fill(0x80808080)  # gray background

        painter = QPainter(pixmap)
        painter.setPen(0xFFFFFFFF)  # white text

        font = painter.font()
        font.setPointSize(max(8, size // 2))
        font.setBold(True)
        painter.setFont(font)

        painter.drawText(pixmap.rect(), Qt.AlignCenter, text)
        painter.end()

        icon = QIcon()
        icon.addPixmap(pixmap)
        return icon

    except Exception as e:
        print(f"warning: failed to create fallback icon: {e}")
        return QIcon()  # empty icon
