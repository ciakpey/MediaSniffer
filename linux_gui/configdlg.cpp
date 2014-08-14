#include "configdlg.h"
#include <pcap.h>

typedef struct
{
	GtkBuilder *builder;
	Config *cfg;
	bool succ;
} Param;

#define ID_WINDOW_PREF "pref"
#define ID_LISTST_ADAPTER "liststore_adapter"
#define ID_BUTT_OK "butt_ok"
#define ID_TREE_ADAPTER "tree_adapter"
#define ID_ENTRY_PORT "entry_port"
#define ID_ENTRY_FILTERWORDS "entry_filterwords"
#define ID_CHECK_FILTERIDURL "check_filteridurl"
#define ID_CHECK_FILTER "check_filter"
#define ID_CHECK_CHKUPDATE "check_chkupdate"

static const gchar kConfigDlg_Ui[] =
"<interface>"
	"<object class=\"GtkListStore\" id=\""ID_LISTST_ADAPTER"\">"
		"<columns>"
			"<column type=\"gchararray\"/>"
			"<column type=\"gchararray\"/>"
			"<column type=\"gchararray\"/>"
		"</columns>"
	"</object>"
	"<object class=\"GtkWindow\" id=\""ID_WINDOW_PREF"\">"
		"<property name=\"title\">Preferences</property>"
		"<property name=\"border_width\">10</property>"
		"<property name=\"modal\">TRUE</property>"
		"<property name=\"resizable\">FALSE</property>"
		"<property name=\"window_position\">GTK_WIN_POS_CENTER</property>"
		"<child>"
			"<object class=\"GtkVBox\" id=\"vbox1\">"
				"<child>"
					"<object class=\"GtkLabel\" id=\"label1\">"
						"<property name=\"xalign\">0.02</property>"
						"<property name=\"label\">Network Adapter</property>"
					"</object>"
				"</child>"
				"<child>"
					"<object class=\"GtkScrolledWindow\" id=\"scrolledwindow1\">"
						"<property name=\"hscrollbar_policy\">automatic</property>"
						"<property name=\"vscrollbar_policy\">automatic</property>"
						"<property name=\"shadow_type\">etched-in</property>"
						"<child>"
							"<object class=\"GtkTreeView\" id=\""ID_TREE_ADAPTER"\">"
								"<property name=\"model\">"ID_LISTST_ADAPTER"</property>"
								"<property name=\"headers_clickable\">FALSE</property>"
								"<property name=\"enable_grid_lines\">both</property>"
								"<property name=\"height_request\">150</property>"
								"<child>"
									"<object class=\"GtkTreeViewColumn\" id=\"tvc_adapter\">"
										"<property name=\"title\">Adapter Name</property>"
										"<property name=\"resizable\">TRUE</property>"
										"<property name=\"sizing\">GTK_TREE_VIEW_COLUMN_FIXED</property>"
										"<property name=\"fixed_width\">100</property>"
										"<child>"
											"<object class=\"GtkCellRendererText\" id=\"rend1\"/>"
											"<attributes>"
												"<attribute name=\"text\">0</attribute>"
											"</attributes>"
										"</child>"
									"</object>"
								"</child>"
								"<child>"
									"<object class=\"GtkTreeViewColumn\" id=\"tvc_ip\">"
										"<property name=\"title\">IP Address</property>"
										"<property name=\"resizable\">TRUE</property>"
										"<property name=\"sizing\">GTK_TREE_VIEW_COLUMN_FIXED</property>"
										"<property name=\"fixed_width\">120</property>"
										"<child>"
											"<object class=\"GtkCellRendererText\" id=\"rend2\"/>"
											"<attributes>"
												"<attribute name=\"text\">1</attribute>"
											"</attributes>"
										"</child>"
									"</object>"
								"</child>"
								"<child>"
									"<object class=\"GtkTreeViewColumn\" id=\"tvc_desc\">"
										"<property name=\"title\">Description</property>"
										"<property name=\"resizable\">TRUE</property>"
										"<property name=\"sizing\">GTK_TREE_VIEW_COLUMN_FIXED</property>"
										"<property name=\"fixed_width\">250</property>"
										"<child>"
											"<object class=\"GtkCellRendererText\" id=\"rend3\"/>"
											"<attributes>"
												"<attribute name=\"text\">2</attribute>"
											"</attributes>"
										"</child>"
									"</object>"
								"</child>"
							"</object>"
						"</child>"
					"</object>"
				"</child>"
				"<child>"
					"<object class=\"GtkHBox\" id=\"hbox1\">"
						"<child>"
							"<object class=\"GtkLabel\" id=\"label2\">"
								"<property name=\"label\">Sniff Port:</property>"
							"</object>"
							"<packing>"
								"<property name=\"expand\">FALSE</property>"
							"</packing>"
						"</child>"
						"<child>"
							"<object class=\"GtkEntry\" id=\""ID_ENTRY_PORT"\">"
								"<property name=\"max_length\">5</property>"
								"<property name=\"width_chars\">5</property>"
								"<property name=\"activates_default\">TRUE</property>"
							"</object>"
							"<packing>"
								"<property name=\"expand\">FALSE</property>"
							"</packing>"
						"</child>"
						"<child>"
							"<object class=\"GtkCheckButton\" id=\""ID_CHECK_FILTERIDURL"\">"
								"<property name=\"label\">Filter identical URLs (Same URL will appear only once.)</property>"
							"</object>"
							"<packing>"
								"<property name=\"padding\">15</property>"
							"</packing>"
						"</child>"
					"</object>"
					"<packing>"
						"<property name=\"padding\">5</property>"
					"</packing>"
				"</child>"
				"<child>"
					"<object class=\"GtkCheckButton\" id=\""ID_CHECK_FILTER"\">"
						"<property name=\"label\">Capture URLs with the following extensions:</property>"
					"</object>"
				"</child>"
				"<child>"
					"<object class=\"GtkEntry\" id=\""ID_ENTRY_FILTERWORDS"\">"
						"<property name=\"activates_default\">TRUE</property>"
					"</object>"
				"</child>"
				"<child>"
					"<object class=\"GtkHBox\" id=\"hbox2\">"
						"<child>"
							"<object class=\"GtkCheckButton\" id=\""ID_CHECK_CHKUPDATE"\">"
								"<property name=\"label\">Check for updates on startup</property>"
							"</object>"
						"</child>"
						"<child>"
							"<object class=\"GtkButton\" id=\""ID_BUTT_OK"\">"
								"<property name=\"label\">"GTK_STOCK_OK"</property>"
								"<property name=\"use_stock\">TRUE</property>"
								"<property name=\"can_default\">TRUE</property>"
								"<property name=\"has_default\">TRUE</property>"
							"</object>"
						"</child>"
					"</object>"
					"<packing>"
						"<property name=\"padding\">5</property>"
					"</packing>"
				"</child>"
			"</object>"
		"</child>"
	"</object>"
"</interface>";

static void OnFilter( GtkToggleButton *tgbutt, GtkEntry *entry )
{
	gtk_widget_set_sensitive( GTK_WIDGET(entry), gtk_toggle_button_get_active( tgbutt ) );
}//end OnFilter

static void OnCfgOK( GtkButton *button, Param *p )
{
	GtkWindow *win;
	GtkWidget *dlg;
	GtkTreeView *treeview;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GValue val = {0};
	const gchar *txt;

	win = GTK_WINDOW(gtk_builder_get_object( p->builder, ID_WINDOW_PREF ));

	treeview = GTK_TREE_VIEW(gtk_builder_get_object( p->builder, ID_TREE_ADAPTER ));
	selection = gtk_tree_view_get_selection( treeview );
	if( !gtk_tree_selection_get_selected( selection, &model, &iter ) )
		{
		dlg = gtk_message_dialog_new( win, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Please select a network adapter!" );
		gtk_dialog_run( GTK_DIALOG( dlg ) );
		gtk_widget_destroy( dlg );
		gtk_widget_grab_focus( GTK_WIDGET(treeview) );
		return;
		}//end if
	gtk_tree_model_get_value( model, &iter, 0, &val );
	strcpy( p->cfg->adapter, g_value_get_string( &val ) );
	g_value_unset( &val );

	p->cfg->dst_port = atoi( gtk_entry_get_text( GTK_ENTRY(gtk_builder_get_object( p->builder, ID_ENTRY_PORT )) ) );

	p->cfg->filteridurl = gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON(gtk_builder_get_object( p->builder, ID_CHECK_FILTERIDURL )) );

	p->cfg->filter = gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON(gtk_builder_get_object( p->builder, ID_CHECK_FILTER )) );
	txt = gtk_entry_get_text( GTK_ENTRY(gtk_builder_get_object( p->builder, ID_ENTRY_FILTERWORDS )) );
	strncpy( p->cfg->filterwords, txt, sizeof(p->cfg->filterwords) );

	p->cfg->checkupdate = gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON(gtk_builder_get_object( p->builder, ID_CHECK_CHKUPDATE )) );

	p->succ = true;

	gtk_main_quit();
}//end OnCfgOK

bool EditConfigDlg( Config* cfg )
{
	static GtkBuilder *builder = NULL;
	Param p;
	GtkWidget *win;
	GtkEntry *entry;
	GtkToggleButton *tgbutt;
	GtkTreeView *treeview;
	GtkTreePath *treepath;
	GtkListStore *lstore;
	gchar *path;

	char buff[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	int i;

	p.succ = false;

	if( builder == NULL )
		{
		builder = gtk_builder_new();
		gtk_builder_add_from_string( builder, kConfigDlg_Ui, -1, NULL );

		//Network Adapter
		treeview = GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_ADAPTER ));
		lstore = GTK_LIST_STORE(gtk_tree_view_get_model( treeview ));
		pcap_findalldevs( &alldevs, buff );
		for( i = 0, d = alldevs; d != NULL; d = d->next, ++i )
			{
			for( a = d->addresses; a != NULL; a = a->next )
				{
				if( a->addr->sa_family == AF_INET )
					{
					break;
					}//end if
				}//end for
			gtk_list_store_insert_with_values( lstore, NULL, i,
				0, d->name,
				1, (a != NULL) ? inet_ntoa( reinterpret_cast<struct sockaddr_in*>(a->addr)->sin_addr ) : "N/A",
				2, (d->description != NULL) ? d->description : "",
				-1 );
			if( strcmp( d->name, cfg->adapter ) == 0 )
				{
				// select this row
				treepath = gtk_tree_path_new_from_indices( i, -1 );
				gtk_tree_view_set_cursor( treeview, treepath, NULL, FALSE );
				gtk_tree_path_free( treepath );
				}//end if
			}//end for
		pcap_freealldevs( alldevs );

		gtk_entry_set_text( GTK_ENTRY(gtk_builder_get_object( builder, ID_ENTRY_PORT )), itoa( cfg->dst_port, buff, 10 ) );

		gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON(gtk_builder_get_object( builder, ID_CHECK_FILTERIDURL )), cfg->filteridurl );

		tgbutt = GTK_TOGGLE_BUTTON(gtk_builder_get_object( builder, ID_CHECK_FILTER ));
		gtk_toggle_button_set_active( tgbutt, cfg->filter );
		entry = GTK_ENTRY(gtk_builder_get_object( builder, ID_ENTRY_FILTERWORDS ));
		gtk_entry_set_text( entry, cfg->filterwords );
		OnFilter( tgbutt, entry );
		g_signal_connect( tgbutt, "toggled", G_CALLBACK(OnFilter), entry );

		gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON(gtk_builder_get_object( builder, ID_CHECK_CHKUPDATE )), cfg->checkupdate );

		p.builder = builder;
		p.cfg = cfg;
		g_signal_connect( gtk_builder_get_object( builder, ID_BUTT_OK ), "clicked", G_CALLBACK(OnCfgOK), &p );

		// show window
		win = GTK_WIDGET(gtk_builder_get_object( builder, ID_WINDOW_PREF ));
		g_signal_connect( win, "delete-event", G_CALLBACK(gtk_main_quit), NULL );
		path = gnome_program_locate_file( NULL, GNOME_FILE_DOMAIN_APP_PIXMAP, kIconFile, TRUE, NULL );
		if( path != NULL )
			{
			gtk_window_set_icon_from_file( GTK_WINDOW(win), path, NULL );
			g_free( path );
			}//end if

		gtk_widget_show_all( win );
		gtk_main();
		gtk_widget_destroy( win );
		g_object_unref( builder );
		builder = NULL;
		}//end if
	
	return p.succ;
}//end EditConfigDlg
