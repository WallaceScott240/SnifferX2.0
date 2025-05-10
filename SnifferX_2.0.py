import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import threading
import random
import time
from datetime import datetime

class SnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("SnifferX 2.0")
        master.geometry("1000x700")
        master.config(bg="#2C3E50")
        
        # Set window icon (replace with actual icon path)
        try:
            master.iconbitmap('sniffer_icon.ico')
        except:
            pass
        
        # Configure grid weights for responsive layout
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)
        
        # Main layout frame
        self.main_frame = tk.Frame(master, bg="#2C3E50")
        self.main_frame.pack(padx=20, pady=20, expand=True, fill=tk.BOTH)
        
        # Configure grid weights for main frame
        self.main_frame.grid_rowconfigure(0, weight=1)  # Text area
        self.main_frame.grid_rowconfigure(1, weight=0)  # Filters
        self.main_frame.grid_rowconfigure(2, weight=0)  # Filter display
        self.main_frame.grid_rowconfigure(3, weight=0)  # Statistics
        self.main_frame.grid_rowconfigure(4, weight=0)  # Controls
        self.main_frame.grid_rowconfigure(5, weight=0)  # Status
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # Output text area with improved styling
        self.text_area = scrolledtext.ScrolledText(
            self.main_frame, 
            height=15, 
            width=100, 
            bg="#34495E", 
            fg="#ECF0F1", 
            font=("Consolas", 10),
            wrap=tk.WORD,
            insertbackground="white",
            selectbackground="#2980B9"
        )
        self.text_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        
        # Add right-click context menu
        self.setup_context_menu()
        
        # Filter section with improved layout
        self.filters_frame = tk.LabelFrame(
            self.main_frame, 
            text="Packet Filters", 
            bg="#2C3E50", 
            fg="#ECF0F1", 
            font=("Arial", 12, "bold"),
            relief=tk.GROOVE,
            bd=2
        )
        self.filters_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew", padx=10)
        
        # Protocol filters
        self.tcp_var = tk.IntVar(value=1)
        self.udp_var = tk.IntVar(value=1)
        self.icmp_var = tk.IntVar(value=1)
        self.other_var = tk.IntVar(value=0)
        
        self.create_filter_checkbox(self.filters_frame, "TCP", self.tcp_var)
        self.create_filter_checkbox(self.filters_frame, "UDP", self.udp_var)
        self.create_filter_checkbox(self.filters_frame, "ICMP", self.icmp_var)
        self.create_filter_checkbox(self.filters_frame, "Other", self.other_var)
        
        # IP address filter
        tk.Label(
            self.filters_frame, 
            text="IP Filter:", 
            bg="#2C3E50", 
            fg="#ECF0F1", 
            font=("Arial", 10)
        ).pack(side=tk.LEFT, padx=(20, 5), pady=5)
        
        self.ip_filter_var = tk.StringVar()
        self.ip_filter_entry = tk.Entry(
            self.filters_frame, 
            textvariable=self.ip_filter_var, 
            bg="#34495E", 
            fg="#ECF0F1", 
            insertbackground="white",
            width=20,
            font=("Arial", 10)
        )
        self.ip_filter_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.ip_filter_entry.bind("<Return>", lambda e: self.update_filter_display())
        
        # Port filter
        tk.Label(
            self.filters_frame, 
            text="Port Filter:", 
            bg="#2C3E50", 
            fg="#ECF0F1", 
            font=("Arial", 10)
        ).pack(side=tk.LEFT, padx=(20, 5), pady=5)
        
        self.port_filter_var = tk.StringVar()
        self.port_filter_entry = tk.Entry(
            self.filters_frame, 
            textvariable=self.port_filter_var, 
            bg="#34495E", 
            fg="#ECF0F1", 
            insertbackground="white",
            width=10,
            font=("Arial", 10)
        )
        self.port_filter_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.port_filter_entry.bind("<Return>", lambda e: self.update_filter_display())
        
        # Filter display label
        self.filter_display = tk.Label(
            self.main_frame,
            text="Active Filters: None",
            anchor="w",
            bg="#2C3E50",
            fg="#ECF0F1",
            font=("Arial", 10)
        )
        self.filter_display.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="w")
        
        # Statistics display
        self.stats_frame = tk.LabelFrame(
            self.main_frame, 
            text="Packet Statistics", 
            bg="#2C3E50", 
            fg="#ECF0F1", 
            font=("Arial", 12, "bold"),
            relief=tk.GROOVE,
            bd=2
        )
        self.stats_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew", padx=10)
        
        self.packet_counters = {
            'TCP': tk.IntVar(value=0),
            'UDP': tk.IntVar(value=0),
            'ICMP': tk.IntVar(value=0),
            'Other': tk.IntVar(value=0),
            'Total': tk.IntVar(value=0)
        }
        
        for i, (proto, var) in enumerate(self.packet_counters.items()):
            tk.Label(
                self.stats_frame, 
                text=f"{proto}:", 
                bg="#2C3E50", 
                fg="#ECF0F1", 
                font=("Arial", 10)
            ).grid(row=0, column=i*2, padx=(10 if i==0 else 5, 5), pady=5, sticky="e")
            
            tk.Label(
                self.stats_frame, 
                textvariable=var, 
                bg="#2C3E50", 
                fg="#3498DB", 
                font=("Arial", 10, "bold")
            ).grid(row=0, column=i*2+1, padx=(0, 10 if i==len(self.packet_counters)-1 else 20), pady=5, sticky="w")
        
        # Control buttons with improved layout
        self.controls_frame = tk.Frame(self.main_frame, bg="#2C3E50")
        self.controls_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        self.start_button = self.create_button(self.controls_frame, "Start Sniffing", self.start_sniffing)
        self.stop_button = self.create_button(self.controls_frame, "Stop Sniffing", self.stop_sniffing, state=tk.DISABLED)
        self.clear_button = self.create_button(self.controls_frame, "Clear Output", self.clear_output)
        self.save_button = self.create_button(self.controls_frame, "Save Output", self.save_output)
        self.export_button = self.create_button(self.controls_frame, "Export as CSV", self.export_csv)
        
        # Status bar with progress indicator
        self.status_frame = tk.Frame(self.main_frame, bg="#2C3E50")
        self.status_frame.grid(row=5, column=0, columnspan=3, sticky="ew", padx=10, pady=5)
        
        self.status_bar = tk.Label(
            self.status_frame, 
            text="Status: Ready", 
            anchor="w", 
            relief=tk.SUNKEN, 
            bg="#34495E", 
            fg="#ECF0F1", 
            font=("Arial", 10),
            padx=10
        )
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress = ttk.Progressbar(
            self.status_frame, 
            orient=tk.HORIZONTAL, 
            mode='determinate', 
            length=100
        )
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Sniffer control variables
        self.sniff_thread = None
        self.sniffing_active = False
        self.packet_history = []
        
        # Bind filter updates
        for var in [self.tcp_var, self.udp_var, self.icmp_var, self.other_var]:
            var.trace_add("write", self.update_start_button_state)
        
        # Initialize filter display
        self.update_filter_display()
        
        # Bind window close event
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_context_menu(self):
        """Add right-click context menu to text area"""
        self.context_menu = tk.Menu(self.text_area, tearoff=0, bg="#34495E", fg="#ECF0F1")
        self.context_menu.add_command(label="Copy", command=self.copy_text)
        self.context_menu.add_command(label="Clear", command=self.clear_output)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=self.select_all_text)
        
        self.text_area.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        """Show context menu on right-click"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def copy_text(self):
        """Copy selected text to clipboard"""
        self.master.clipboard_clear()
        self.master.clipboard_append(self.text_area.selection_get())
    
    def select_all_text(self):
        """Select all text in the output area"""
        self.text_area.tag_add(tk.SEL, "1.0", tk.END)
        self.text_area.mark_set(tk.INSERT, "1.0")
        self.text_area.see(tk.INSERT)
        return 'break'
    
    def create_filter_checkbox(self, frame, text, variable):
        """Create a styled filter checkbox"""
        check_button = tk.Checkbutton(
            frame, 
            text=text, 
            variable=variable, 
            bg="#2C3E50", 
            fg="#ECF0F1", 
            font=("Arial", 10), 
            selectcolor="#34495E", 
            activebackground="#2C3E50",
            activeforeground="#ECF0F1"
        )
        check_button.pack(side=tk.LEFT, padx=10, pady=5)
        return check_button
    
    def create_button(self, frame, text, command, state=tk.NORMAL):
        """Create a styled button with hover effects"""
        button = tk.Button(
            frame, 
            text=text, 
            command=command, 
            state=state, 
            bg="#2980B9", 
            fg="white", 
            font=("Arial", 10, "bold"), 
            relief=tk.RAISED, 
            bd=2, 
            height=1, 
            width=15, 
            activebackground="#3498DB", 
            activeforeground="white", 
            highlightbackground="#2C3E50",
            cursor="hand2"
        )
        button.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Hover effects
        button.bind("<Enter>", lambda e: button.config(bg="#3498DB"))
        button.bind("<Leave>", lambda e: button.config(bg="#2980B9"))
        
        return button
    
    def get_filters(self):
        """Get all active filters"""
        filters = []
        if self.tcp_var.get(): filters.append('TCP')
        if self.udp_var.get(): filters.append('UDP')
        if self.icmp_var.get(): filters.append('ICMP')
        if self.other_var.get(): filters.append('Other')
        return filters
    
    def update_output(self, packet_details, protocol):
        """Update the output area with new packet details"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_packet = f"[{timestamp}] {packet_details}"
        
        # Add to history
        self.packet_history.append((timestamp, protocol, packet_details))
        
        # Update UI in thread-safe way
        self.master.after(0, self._insert_text, formatted_packet, protocol)
    
    def _insert_text(self, packet_details, protocol):
        """Thread-safe text insertion with protocol-based coloring"""
        # Configure tag colors for different protocols
        self.text_area.tag_config('TCP', foreground="#1ABC9C")
        self.text_area.tag_config('UDP', foreground="#3498DB")
        self.text_area.tag_config('ICMP', foreground="#E74C3C")
        self.text_area.tag_config('Other', foreground="#9B59B6")
        
        # Insert text with appropriate tag
        self.text_area.insert(tk.END, packet_details + "\n", protocol)
        self.text_area.yview(tk.END)
        
        # Update statistics
        if protocol in self.packet_counters:
            self.packet_counters[protocol].set(self.packet_counters[protocol].get() + 1)
            self.packet_counters['Total'].set(self.packet_counters['Total'].get() + 1)
    
    def update_filter_display(self):
        """Update the filter display based on current settings"""
        filters = []
        if self.tcp_var.get(): filters.append('TCP')
        if self.udp_var.get(): filters.append('UDP')
        if self.icmp_var.get(): filters.append('ICMP')
        if self.other_var.get(): filters.append('Other')
        
        ip_filter = self.ip_filter_var.get().strip()
        port_filter = self.port_filter_var.get().strip()
        
        filter_text = "Active Filters: "
        if filters:
            filter_text += f"Protocols: {', '.join(filters)}"
        if ip_filter:
            filter_text += f", IP: {ip_filter}"
        if port_filter:
            filter_text += f", Port: {port_filter}"
        
        if not filters and not ip_filter and not port_filter:
            filter_text = "Active Filters: None"
        
        self.filter_display.config(text=filter_text)
    
    def update_status(self, status, color="#ECF0F1"):
        """Update the status bar"""
        self.status_bar.config(text=f"Status: {status}", fg=color)
    
    def update_start_button_state(self, *args):
        """Enable/disable start button based on filter selection"""
        filters = self.get_filters()
        if filters:
            self.start_button.config(state=tk.NORMAL)
        else:
            self.start_button.config(state=tk.DISABLED)
    
    def start_sniffing(self):
        """Start the packet sniffing process"""
        filters = self.get_filters()
        if not filters:
            messagebox.showwarning("No Filters", "Please select at least one protocol filter!")
            return
        
        # Reset statistics
        for var in self.packet_counters.values():
            var.set(0)
        
        # Update UI
        self.update_status("Sniffing in progress...", color="#2ECC71")
        self.update_filter_display()
        self.progress['value'] = 0  # Reset progress bar
        
        # Start sniffing in a separate thread
        self.sniffing_active = True
        self.sniff_thread = threading.Thread(
            target=self.sniff_packets, 
            args=(filters, self.ip_filter_var.get(), self.port_filter_var.get()),
            daemon=True
        )
        self.sniff_thread.start()
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
    
    def stop_sniffing(self):
        """Stop the packet sniffing process"""
        self.sniffing_active = False
        self.update_status("Sniffer Stopped", color="#E74C3C")
        self.progress.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def sniff_packets(self, protocol_filters, ip_filter, port_filter):
        """Simulate packet sniffing (replace with actual sniffing code)"""
        protocols = ['TCP', 'UDP', 'ICMP', 'Other']
        packet_counter = 0
        
        while self.sniffing_active and packet_counter < 100:  # Limit for simulation
            time.sleep(random.uniform(0.1, 0.5))  # Random delay to simulate real traffic
            
            # Simulate packet data
            protocol = random.choices(
                protocols,
                weights=[0.4, 0.4, 0.1, 0.1]  # Weighted probabilities
            )[0]
            
            # Skip if protocol not in filters
            if protocol not in protocol_filters:
                continue
            
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dst_ip = f"10.0.0.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 53, 3389, 8080])
            size = random.randint(64, 1500)
            
            # Apply IP filter if specified
            if ip_filter and ip_filter not in src_ip and ip_filter not in dst_ip:
                continue
                
            # Apply port filter if specified
            if port_filter and port_filter != str(dst_port):
                continue
            
            packet_details = (
                f"Packet {packet_counter + 1}: "
                f"Src: {src_ip}:{src_port}, "
                f"Dst: {dst_ip}:{dst_port}, "
                f"Protocol: {protocol}, "
                f"Size: {size} bytes"
            )
            
            self.update_output(packet_details, protocol)
            packet_counter += 1
            
            # Update progress
            progress = min(100, packet_counter)
            self.master.after(0, lambda: self.progress.config(value=progress))
        
        self.master.after(0, self.stop_sniffing)
    
    def clear_output(self):
        """Clear the output text area"""
        if not self.text_area.get(1.0, tk.END).strip():
            return
            
        if messagebox.askyesno("Clear Output", "Are you sure you want to clear the output?"):
            self.text_area.delete(1.0, tk.END)
            self.packet_history.clear()
            
            # Reset statistics
            for var in self.packet_counters.values():
                var.set(0)
    
    def save_output(self):
        """Save the output to a text file"""
        if not self.text_area.get(1.0, tk.END).strip():
            messagebox.showwarning("Empty Output", "There is no output to save!")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Output As"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(self.text_area.get(1.0, tk.END))
                messagebox.showinfo("Saved", "Output has been saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def export_csv(self):
        """Export packet data as CSV"""
        if not self.packet_history:
            messagebox.showwarning("No Data", "No packet data to export!")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Packet Data As CSV"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    # Write CSV header
                    file.write("Timestamp,Protocol,Source IP,Source Port,Destination IP,Destination Port,Size\n")
                    
                    # Write packet data
                    for timestamp, protocol, details in self.packet_history:
                        # Parse details (this is simplified for the example)
                        parts = details.split(",")
                        src = parts[0].split(":")[1].strip()
                        dst = parts[1].split(":")[1].strip()
                        size = parts[3].split(":")[1].strip().split()[0]
                        
                        src_ip, src_port = src.split(":")
                        dst_ip, dst_port = dst.split(":")
                        
                        file.write(f'"{timestamp}","{protocol}","{src_ip}","{src_port}","{dst_ip}","{dst_port}","{size}"\n')
                
                messagebox.showinfo("Exported", "Packet data exported to CSV successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")
    
    def on_close(self):
        """Handle window close event"""
        if self.sniffing_active:
            if messagebox.askyesno("Confirm Exit", "Sniffer is still active. Are you sure you want to exit?"):
                self.sniffing_active = False
                if self.sniff_thread and self.sniff_thread.is_alive():
                    self.sniff_thread.join(timeout=1)
                self.master.destroy()
        else:
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    try:
        # Set theme (requires ttkthemes package - pip install ttkthemes)
        from ttkthemes import ThemedTk
        root = ThemedTk(theme="equilux")
    except ImportError:
        pass
    
    app = SnifferGUI(root)
    root.mainloop()