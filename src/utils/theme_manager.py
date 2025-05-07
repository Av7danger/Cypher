import os
import json
from PyQt5.QtWidgets import QApplication, QGraphicsOpacityEffect, QWidget, QLabel
from PyQt5.QtCore import QPropertyAnimation, QEasingCurve, Qt, QObject, pyqtSignal, QVariantAnimation, QPoint, QRect, QTimer
from PyQt5.QtGui import QPalette, QColor, QBrush

class ThemeManager:
    """Manages application themes and styling"""
    
    # Define themes
    LIGHT_THEME = {
        "name": "light",
        "background": "#f5f5f5",
        "foreground": "#333333",
        "accent": "#3498db",
        "secondary_bg": "#ffffff",
        "border": "#cccccc",
        "highlight": "#2980b9",
        "warning": "#e74c3c",
        "success": "#2ecc71"
    }
    
    DARK_THEME = {
        "name": "dark",
        "background": "#222222",  # Darker background for better contrast
        "foreground": "#ffffff",
        "accent": "#3498db",
        "secondary_bg": "#333333",
        "border": "#444444",
        "highlight": "#2980b9",
        "warning": "#e74c3c",
        "success": "#2ecc71"
    }
    
    # Singleton instance
    _instance = None
    
    @classmethod
    def instance(cls):
        """Get singleton instance of theme manager"""
        if cls._instance is None:
            cls._instance = ThemeManager()
        return cls._instance
    
    def __init__(self):
        self.current_theme = self.LIGHT_THEME
        self.config_file = os.path.expanduser("~/.cypher_theme.json")
        self.load_saved_theme()
        
    def load_saved_theme(self):
        """Load saved theme preferences from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r") as f:
                    theme_name = json.load(f).get("theme", "light")
                    if theme_name == "dark":
                        self.current_theme = self.DARK_THEME
        except Exception as e:
            print(f"Error loading theme: {str(e)}")
    
    def save_theme(self):
        """Save current theme preference to file"""
        try:
            with open(self.config_file, "w") as f:
                json.dump({"theme": self.current_theme["name"]}, f)
        except Exception as e:
            print(f"Error saving theme: {str(e)}")
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.current_theme["name"] == "light":
            self.current_theme = self.DARK_THEME
        else:
            self.current_theme = self.LIGHT_THEME
        
        self.apply_theme()
        self.save_theme()
        return self.current_theme
    
    def get_current_theme(self):
        """Get the current theme name"""
        return self.current_theme["name"]
    
    def apply_theme(self):
        """Apply the current theme to the application"""
        app = QApplication.instance()
        
        palette = QPalette()
        
        # Set QPalette colors
        palette.setColor(QPalette.Window, QColor(self.current_theme["background"]))
        palette.setColor(QPalette.WindowText, QColor(self.current_theme["foreground"]))
        palette.setColor(QPalette.Base, QColor(self.current_theme["secondary_bg"]))
        palette.setColor(QPalette.AlternateBase, QColor(self.current_theme["secondary_bg"]).lighter(110))
        palette.setColor(QPalette.ToolTipBase, QColor(self.current_theme["secondary_bg"]))
        palette.setColor(QPalette.ToolTipText, QColor(self.current_theme["foreground"]))
        palette.setColor(QPalette.Text, QColor(self.current_theme["foreground"]))
        palette.setColor(QPalette.Button, QColor(self.current_theme["background"]))
        palette.setColor(QPalette.ButtonText, QColor(self.current_theme["foreground"]))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(self.current_theme["accent"]))
        palette.setColor(QPalette.Highlight, QColor(self.current_theme["highlight"]))
        palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
        
        # Apply palette to the application
        app.setPalette(palette)
        
        # Apply stylesheet for more detailed control
        button_bg = self.current_theme["accent"]
        button_hover = self.current_theme["highlight"]
        tab_bg = QColor(self.current_theme["background"]).lighter(110).name()
        tab_selected_bg = self.current_theme["secondary_bg"]
        border_color = self.current_theme["border"]
        
        app.setStyleSheet(f"""
            QMainWindow, QDialog, QWidget {{
                background-color: {self.current_theme["background"]};
                color: {self.current_theme["foreground"]};
            }}
            
            QGroupBox {{
                border: 1px solid {border_color};
                margin-top: 1.1em;
                padding-top: 0.8em;
                border-radius: 3px;
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px;
                padding: 0 3px;
                background-color: {self.current_theme["background"]};
            }}
            
            QTabWidget::pane {{
                border: 1px solid {border_color};
                background-color: {self.current_theme["secondary_bg"]};
            }}
            
            QTabBar::tab {{
                background-color: {tab_bg};
                padding: 6px 12px;
                margin-right: 2px;
                border: 1px solid {border_color};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                color: {self.current_theme["foreground"]};
            }}
            
            QTabBar::tab:selected {{
                background-color: {tab_selected_bg};
                border-bottom-color: {tab_selected_bg};
            }}
            
            QPushButton {{
                background-color: {button_bg};
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
            }}
            
            QPushButton:hover {{
                background-color: {button_hover};
            }}
            
            QPushButton:disabled {{
                background-color: {self.current_theme["border"]};
                color: {QColor(self.current_theme["foreground"]).lighter(150).name()};
            }}
            
            QLineEdit, QTextEdit, QComboBox, QSpinBox {{
                background-color: {self.current_theme["secondary_bg"]};
                color: {self.current_theme["foreground"]};
                border: 1px solid {border_color};
                border-radius: 3px;
                padding: 4px;
            }}
            
            QTextEdit {{
                selection-background-color: {self.current_theme["highlight"]};
                selection-color: white;
            }}
            
            QComboBox QAbstractItemView {{
                background-color: {self.current_theme["secondary_bg"]};
                color: {self.current_theme["foreground"]};
                selection-background-color: {self.current_theme["highlight"]};
                selection-color: white;
                border: 1px solid {border_color};
            }}
            
            QCheckBox {{
                color: {self.current_theme["foreground"]};
            }}
            
            QCheckBox::indicator:unchecked {{
                border: 1px solid {border_color};
                background-color: {self.current_theme["secondary_bg"]};
            }}
            
            QCheckBox::indicator:checked {{
                border: 1px solid {self.current_theme["highlight"]};
                background-color: {self.current_theme["highlight"]};
            }}
            
            QTableWidget, QListWidget, QTreeWidget {{
                background-color: {self.current_theme["secondary_bg"]};
                alternate-background-color: {QColor(self.current_theme["secondary_bg"]).darker(105).name()};
                color: {self.current_theme["foreground"]};
                gridline-color: {border_color};
                border: 1px solid {border_color};
            }}
            
            QTableWidget::item:selected, QListWidget::item:selected {{
                background-color: {self.current_theme["highlight"]};
                color: white;
            }}
            
            QHeaderView::section {{
                background-color: {QColor(self.current_theme["background"]).darker(110).name()};
                color: {self.current_theme["foreground"]};
                padding: 4px;
                border: 1px solid {border_color};
            }}
            
            QProgressBar {{
                border: 1px solid {border_color};
                border-radius: 3px;
                background-color: {self.current_theme["secondary_bg"]};
                text-align: center;
                color: {self.current_theme["foreground"]};
            }}
            
            QProgressBar::chunk {{
                background-color: {self.current_theme["accent"]};
                width: 10px;
                margin: 0px;
            }}
            
            QMenuBar, QMenuBar::item, QMenu, QMenu::item {{
                background-color: {self.current_theme["background"]};
                color: {self.current_theme["foreground"]};
            }}
            
            QMenuBar::item:selected, QMenu::item:selected {{
                background-color: {self.current_theme["highlight"]};
                color: white;
            }}
            
            QToolTip {{
                background-color: {self.current_theme["secondary_bg"]};
                color: {self.current_theme["foreground"]};
                border: 1px solid {border_color};
            }}
            
            QScrollBar:vertical, QScrollBar:horizontal {{
                background: {self.current_theme["background"]};
                border: 1px solid {border_color};
            }}
            
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
                background: {QColor(self.current_theme["secondary_bg"]).darker(120).name()};
                min-height: 20px;
                border-radius: 3px;
            }}
            
            QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
                background: {QColor(self.current_theme["secondary_bg"]).darker(140).name()};
            }}
            
            QLabel {{
                color: {self.current_theme["foreground"]};
            }}
        """)


class AnimatedWidget(QObject):
    """Provides animations for widgets transitions"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animations = []  # Store active animations
    
    def fade_in(self, widget, duration=300):
        """Fade in animation for a widget."""
        widget.setGraphicsEffect(None)  # Clear any existing effects
        opacity_effect = QGraphicsOpacityEffect()
        widget.setGraphicsEffect(opacity_effect)
        
        animation = QPropertyAnimation(opacity_effect, b"opacity")
        animation.setDuration(duration)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.start()
        
        return animation
    
    def fade_out(self, widget, duration=300):
        """Fade out animation for a widget."""
        opacity_effect = QGraphicsOpacityEffect()
        widget.setGraphicsEffect(opacity_effect)
        
        animation = QPropertyAnimation(opacity_effect, b"opacity")
        animation.setDuration(duration)
        animation.setStartValue(1.0)
        animation.setEndValue(0.0)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.start()
        
        return animation
        
    def slide_in(self, widget, direction="right", duration=300):
        """Slide in animation for a widget.
        
        Args:
            widget: Widget to animate
            direction: Direction to slide from ("left", "right", "top", "bottom")
            duration: Animation duration in milliseconds
        """
        # Store original position
        original_pos = widget.pos()
        
        # Set start position
        if direction == "right":
            widget.move(widget.width(), original_pos.y())
        elif direction == "left":
            widget.move(-widget.width(), original_pos.y())
        elif direction == "bottom":
            widget.move(original_pos.x(), widget.height())
        elif direction == "top":
            widget.move(original_pos.x(), -widget.height())
        
        # Create animation
        anim = QPropertyAnimation(widget, b"pos")
        anim.setEndValue(original_pos)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start()
        
        return anim
    
    def pulse(self, widget, duration=300):
        """Create a pulse animation (growing and shrinking)"""
        # Store original size
        original_size = widget.size()
        
        # Create animation
        anim = QPropertyAnimation(widget, b"size")
        anim.setDuration(duration)
        anim.setStartValue(original_size)
        anim.setEndValue(original_size * 1.05)  # Grow by 5%
        anim.setEasingCurve(QEasingCurve.OutInQuad)
        
        # Create second animation (shrink back)
        anim2 = QPropertyAnimation(widget, b"size")
        anim2.setDuration(duration)
        anim2.setStartValue(original_size * 1.05)
        anim2.setEndValue(original_size)
        anim2.setEasingCurve(QEasingCurve.InOutQuad)
        
        # Start first animation
        anim.start()
        
        # Start second animation when first one finishes
        anim.finished.connect(anim2.start)
        
        return [anim, anim2]
        
    def button_click_effect(self, button, duration=150):
        """Create a button click animation effect"""
        # Store original style
        original_style = button.styleSheet()
        
        # Create color animation using a temporary property
        button.setProperty("clicked", True)
        
        # Change button style temporarily
        darker_bg = QColor(button.palette().color(QPalette.Button)).darker(120).name()
        button.setStyleSheet(
            original_style + f"QPushButton {{ background-color: {darker_bg}; }}"
        )
        
        # Schedule reset of style
        QTimer.singleShot(duration, lambda: button.setStyleSheet(original_style))
        
        # Also add a tiny scale animation
        return self.quick_scale(button, 0.95, duration)
    
    def quick_scale(self, widget, scale_factor=0.95, duration=100):
        """Quick scale down and up animation using geometry instead of transform"""
        try:
            # Scale down animation
            anim1 = QPropertyAnimation(widget, b"geometry")
            original_geo = widget.geometry()
            center = original_geo.center()
            scaled_width = int(original_geo.width() * scale_factor)
            scaled_height = int(original_geo.height() * scale_factor)
            scaled_geo = QRect(
                center.x() - scaled_width // 2,
                center.y() - scaled_height // 2,
                scaled_width,
                scaled_height
            )
            
            anim1.setDuration(duration // 2)
            anim1.setStartValue(original_geo)
            anim1.setEndValue(scaled_geo)
            anim1.setEasingCurve(QEasingCurve.OutQuad)
            
            # Scale up animation
            anim2 = QPropertyAnimation(widget, b"geometry")
            anim2.setDuration(duration // 2)
            anim2.setStartValue(scaled_geo)
            anim2.setEndValue(original_geo)
            anim2.setEasingCurve(QEasingCurve.OutQuad)
            
            # Sequence the animations
            anim1.finished.connect(anim2.start)
            anim1.start()
            
            return [anim1, anim2]
        except Exception as e:
            # Fallback to simple fade animation if scaling doesn't work
            print(f"Warning: Scale animation failed, using fade instead: {str(e)}")
            return self.fade_in(widget, duration)
    
    def slide_transition(self, old_widget, new_widget, direction="left", duration=300):
        """Transition between two widgets with a slide effect"""
        if old_widget.parent() != new_widget.parent():
            print("Widgets must have the same parent for slide transition")
            return
        
        parent = old_widget.parent()
        
        # Make sure new widget is on top and visible
        new_widget.raise_()
        new_widget.show()
        
        # Set initial position for new widget (off-screen)
        if direction == "left":
            new_widget.move(parent.width(), new_widget.y())
            end_pos_old = QPoint(-old_widget.width(), old_widget.y())
            end_pos_new = QPoint(old_widget.x(), new_widget.y())
        elif direction == "right":
            new_widget.move(-new_widget.width(), new_widget.y())
            end_pos_old = QPoint(parent.width(), old_widget.y())
            end_pos_new = QPoint(old_widget.x(), new_widget.y())
        elif direction == "up":
            new_widget.move(new_widget.x(), parent.height())
            end_pos_old = QPoint(old_widget.x(), -old_widget.height())
            end_pos_new = QPoint(new_widget.x(), old_widget.y())
        elif direction == "down":
            new_widget.move(new_widget.x(), -new_widget.height())
            end_pos_old = QPoint(old_widget.x(), parent.height())
            end_pos_new = QPoint(new_widget.x(), old_widget.y())
        
        # Animate old widget out
        anim_old = QPropertyAnimation(old_widget, b"pos")
        anim_old.setDuration(duration)
        anim_old.setEndValue(end_pos_old)
        anim_old.setEasingCurve(QEasingCurve.OutCubic)
        
        # Animate new widget in
        anim_new = QPropertyAnimation(new_widget, b"pos")
        anim_new.setDuration(duration)
        anim_new.setEndValue(end_pos_new)
        anim_new.setEasingCurve(QEasingCurve.OutCubic)
        
        # Start both animations
        anim_old.start()
        anim_new.start()
        
        # Hide old widget when done
        anim_old.finished.connect(lambda: old_widget.hide())
        
        return [anim_old, anim_new]
    
    def color_transition(self, widget, start_color, end_color, property_name, duration=300):
        """Animate a color property change"""
        from PyQt5.QtCore import QVariantAnimation, QAbstractAnimation
        
        # Create animation
        anim = QVariantAnimation()
        anim.setDuration(duration)
        anim.setStartValue(start_color)
        anim.setEndValue(end_color)
        
        # Update stylesheet on value changed
        def update_stylesheet(color):
            widget.setStyleSheet(
                widget.styleSheet() + f"{widget.objectName()} {{ {property_name}: {color.name()}; }}"
            )
        
        anim.valueChanged.connect(update_stylesheet)
        anim.start()
        
        return anim
        
    def loading_spinner(self, parent, size=40, color=None):
        """Create a loading spinner animation widget"""
        from PyQt5.QtWidgets import QLabel
        from PyQt5.QtCore import QTimer
        
        # If no color specified, use accent color from theme
        if not color:
            theme_manager = ThemeManager.instance()
            color = theme_manager.current_theme["accent"]
        
        # Create spinner widget
        spinner = QLabel(parent)
        spinner.setFixedSize(size, size)
        spinner.setAlignment(Qt.AlignCenter)
        
        # Use CSS animation for rotation to avoid QPainter conflicts
        spinner.setStyleSheet(f"""
            background-color: transparent;
            border: 3px solid {color};
            border-radius: {size // 2}px;
            border-top-color: transparent;
            animation: spin 1s linear infinite;
            
            @keyframes spin {{
                from {{ transform: rotate(0deg); }}
                to {{ transform: rotate(360deg); }}
            }}
        """)
        
        # Add method to stop the animation
        def stop_animation():
            spinner.hide()
            spinner.deleteLater()
        
        spinner.stop = stop_animation
        
        return spinner
    
    def notify_animation(self, widget, highlight_color=None, duration=400):
        """Create a pulsing border highlight animation for notifications"""
        if not highlight_color:
            # Use warning color from theme if none specified
            theme_manager = ThemeManager.instance()
            highlight_color = theme_manager.current_theme["warning"]
        
        # Store original style
        original_style = widget.styleSheet()
        
        # Create highlight style
        highlight_style = original_style + f"""
            border: 2px solid {highlight_color};
            border-radius: 4px;
        """
        
        # Set highlight style
        widget.setStyleSheet(highlight_style)
        
        # Create opacity effect for pulsing
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        
        # Create pulsing animation
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(duration // 2)
        anim.setStartValue(1.0)
        anim.setEndValue(0.4)
        anim.setEasingCurve(QEasingCurve.InOutQuad)
        
        # Create reverse animation
        anim2 = QPropertyAnimation(effect, b"opacity")
        anim2.setDuration(duration // 2)
        anim2.setStartValue(0.4)
        anim2.setEndValue(1.0)
        anim2.setEasingCurve(QEasingCurve.InOutQuad)
        
        # Chain animations to create pulsing effect
        anim.finished.connect(anim2.start)
        anim2.finished.connect(anim.start)
        
        # Start the animation
        anim.start()
        
        # Create a function to stop the animation
        def stop_animation():
            anim.stop()
            anim2.stop()
            widget.setStyleSheet(original_style)
            widget.setGraphicsEffect(None)
        
        # Schedule stopping after 2 seconds (5 pulses)
        QTimer.singleShot(duration * 5, stop_animation)
        
        return [anim, anim2, stop_animation]
    
    def shake(self, widget, distance=10, duration=300, shakes=3):
        """Create a shake animation (useful for error notifications)"""
        # Save original position
        original_pos = widget.pos()
        
        # Create animation
        anim = QPropertyAnimation(widget, b"pos")
        anim.setDuration(duration)
        
        # Calculate keyframes for shaking
        keyframes = []
        for i in range(shakes * 2 + 1):
            x_offset = distance if i % 2 else -distance
            if i == shakes * 2:  # Last keyframe
                x_offset = 0
            keyframes.append((i / (shakes * 2), QPoint(original_pos.x() + x_offset, original_pos.y())))
        
        # Add keyframes to animation
        for i, (step, pos) in enumerate(keyframes):
            anim.setKeyValueAt(step, pos)
        
        # Start animation
        anim.start()
        
        return anim