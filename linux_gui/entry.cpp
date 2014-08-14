#include "../MediaSniffer/MediaSniffer.h"
#include "configdlg.h"
#include "update.h"
#include "uicommon.h"
#include <gdk/gdkkeysyms.h>
#include <stdlib.h>
#include <string>

using namespace std;

#define DATADIR PREFIX"/share"

#define LIBDIR PREFIX"/lib"
#define SYSCONFDIR PREFIX"/etc"

#define DLG_TITLE "Media Sniffer"
const char kConfigFile[] = "mediasniffer.ini";
const char kRunAsRoot[] = "Please run as root.";
const char kHomePage[] = "http://sf.net/projects/mediasniffer/";


MediaSniffer *ms = NULL;
char cfgfile[MAX_PATH];
Config cfg;

char url_filter[512];
char ua_filter[512];

#define ID_WINDOW_MAIN "main"
#define ID_LISTST_SNIFF "liststore_sniff"
#define ID_TREE_SNIFF "tree_sniff"
#define ID_COMBO_URLF "combo_urlf"
#define ID_COMBO_UAF "combo_uaf"
#define ID_BUTT_START "butt_start"
#define ID_BUTT_STOP "butt_stop"
#define ID_BUTT_APPLY "butt_apply"
#define ID_MENU_START "menu_start"
#define ID_MENU_STOP "menu_stop"
#define ID_MENU_PREF "menu_pref"
#define ID_MENU_UPDATE "menu_update"
#define ID_MENU_ABOUT "menu_about_ms"

static const gchar kMainDlg_Ui[] =
"<interface>"
	"<object class=\"GtkListStore\" id=\""ID_LISTST_SNIFF"\">"
		"<columns>"
			"<column type=\"gchararray\"/>"
			"<column type=\"gchararray\"/>"
		"</columns>"
	"</object>"
	"<object class=\"GtkWindow\" id=\""ID_WINDOW_MAIN"\">"
		"<property name=\"modal\">TRUE</property>"
		"<property name=\"window_position\">GTK_WIN_POS_CENTER</property>"
		"<child>"
			"<object class=\"GtkVBox\" id=\"vbox1\">"
				"<child>"
					"<object class=\"GtkMenuBar\" id=\"menubar\">"
						"<child>"
							"<object class=\"GtkMenuItem\" id=\"menu_sniff\">"
								"<property name=\"label\">_Sniff</property>"
								"<property name=\"use_underline\">TRUE</property>"
								"<child type=\"submenu\">"
									"<object class=\"GtkMenu\" id=\"menu1\">"
										"<child>"
											"<object class=\"GtkMenuItem\" id=\""ID_MENU_START"\">"
												"<property name=\"label\">_Start Stniff</property>"
												"<property name=\"use_underline\">TRUE</property>"
											"</object>"
										"</child>"
										"<child>"
											"<object class=\"GtkMenuItem\" id=\""ID_MENU_STOP"\">"
												"<property name=\"label\">Sto_p Sniff</property>"
												"<property name=\"use_underline\">TRUE</property>"
											"</object>"
										"</child>"
									"</object>"
								"</child>"
							"</object>"
						"</child>"
						"<child>"
							"<object class=\"GtkMenuItem\" id=\"menu_edit\">"
								"<property name=\"label\">_Edit</property>"
								"<property name=\"use_underline\">TRUE</property>"
								"<child type=\"submenu\">"
									"<object class=\"GtkMenu\" id=\"menu2\">"
										"<child>"
											"<object class=\"GtkMenuItem\" id=\""ID_MENU_PREF"\">"
												"<property name=\"label\">_Preferences</property>"
												"<property name=\"use_underline\">TRUE</property>"
											"</object>"
										"</child>"
									"</object>"
								"</child>"
							"</object>"
						"</child>"
						"<child>"
							"<object class=\"GtkMenuItem\" id=\"menu_about\">"
								"<property name=\"label\">_About</property>"
								"<property name=\"use_underline\">TRUE</property>"
								"<child type=\"submenu\">"
									"<object class=\"GtkMenu\" id=\"menu3\">"
										"<child>"
											"<object class=\"GtkMenuItem\" id=\""ID_MENU_UPDATE"\">"
												"<property name=\"label\">_Check for Updates</property>"
												"<property name=\"use_underline\">TRUE</property>"
											"</object>"
										"</child>"
										"<child>"
											"<object class=\"GtkImageMenuItem\" id=\""ID_MENU_ABOUT"\">"
												"<property name=\"label\">_About Media Sniffer</property>"
												"<property name=\"use_underline\">TRUE</property>"
											"</object>"
										"</child>"
									"</object>"
								"</child>"
							"</object>"
						"</child>"
					"</object>"
					"<packing>"
						"<property name=\"expand\">FALSE</property>"
					"</packing>"
				"</child>"
				"<child>"
					"<object class=\"GtkHBox\" id=\"hbox1\">"
						"<child>"
							"<object class=\"GtkVBox\" id=\"vbox2\">"
								"<property name=\"width_request\">70</property>"
								"<property name=\"spacing\">5</property>"
								"<child>"
									"<object class=\"GtkButton\" id=\""ID_BUTT_START"\">"
										"<property name=\"label\">Start</property>"
									"</object>"
									"<packing>"
										"<property name=\"fill\">FALSE</property>"
									"</packing>"
								"</child>"
								"<child>"
									"<object class=\"GtkButton\" id=\""ID_BUTT_STOP"\">"
										"<property name=\"label\">Stop</property>"
									"</object>"
									"<packing>"
										"<property name=\"fill\">FALSE</property>"
									"</packing>"
								"</child>"
							"</object>"
							"<packing>"
								"<property name=\"expand\">FALSE</property>"
								"<property name=\"padding\">10</property>"
							"</packing>"
						"</child>"
						"<child>"
							"<object class=\"GtkVSeparator\" id=\"vseparator1\"/>"
							"<packing>"
								"<property name=\"expand\">FALSE</property>"
							"</packing>"
						"</child>"
						"<child>"
							"<object class=\"GtkVBox\" id=\"vbox3\">"
								"<property name=\"width_request\">400</property>"
								"<property name=\"spacing\">5</property>"
								"<child>"
									"<object class=\"GtkHBox\" id=\"hbox2\">"
										"<child>"
											"<object class=\"GtkLabel\" id=\"label1\">"
												"<property name=\"label\">URL Filter:</property>"
											"</object>"
											"<packing>"
												"<property name=\"expand\">FALSE</property>"
												"<property name=\"padding\">5</property>"
											"</packing>"
										"</child>"
										"<child>"
											"<object class=\"GtkComboBoxEntry\" id=\""ID_COMBO_URLF"\">"
												"<child internal-child=\"entry\">"
													"<object class=\"GtkEntry\" id=\"entry_urlf\">"
														"<property name=\"activates_default\">TRUE</property>"
													"</object>"
												"</child>"
											"</object>"
										"</child>"
									"</object>"
								"</child>"
								"<child>"
									"<object class=\"GtkHBox\" id=\"hbox3\">"
										"<child>"
											"<object class=\"GtkLabel\" id=\"label2\">"
												"<property name=\"label\">User Agent Filter:</property>"
											"</object>"
											"<packing>"
												"<property name=\"expand\">FALSE</property>"
												"<property name=\"padding\">5</property>"
											"</packing>"
										"</child>"
										"<child>"
											"<object class=\"GtkComboBoxEntry\" id=\""ID_COMBO_UAF"\">"
												"<child internal-child=\"entry\">"
													"<object class=\"GtkEntry\" id=\"entry_uaf\">"
														"<property name=\"activates_default\">TRUE</property>"
													"</object>"
												"</child>"
											"</object>"
										"</child>"
									"</object>"
								"</child>"
							"</object>"
						"</child>"
						"<child>"
							"<object class=\"GtkButton\" id=\""ID_BUTT_APPLY"\">"
								"<property name=\"label\">Apply Filters</property>"
								"<property name=\"can_default\">TRUE</property>"
								"<property name=\"has_default\">TRUE</property>"
							"</object>"
							"<packing>"
								"<property name=\"expand\">FALSE</property>"
								"<property name=\"padding\">10</property>"
							"</packing>"
						"</child>"
					"</object>"
					"<packing>"
						"<property name=\"expand\">FALSE</property>"
						"<property name=\"padding\">10</property>"
					"</packing>"
				"</child>"
				"<child>"
					"<object class=\"GtkScrolledWindow\" id=\"scrolledwindow1\">"
						"<property name=\"hscrollbar_policy\">automatic</property>"
						"<property name=\"vscrollbar_policy\">automatic</property>"
						"<property name=\"shadow_type\">etched-in</property>"
						"<child>"
							"<object class=\"GtkTreeView\" id=\""ID_TREE_SNIFF"\">"
								"<property name=\"height_request\">450</property>"
								"<property name=\"model\">"ID_LISTST_SNIFF"</property>"
								"<property name=\"headers_clickable\">FALSE</property>"
								"<property name=\"rubber_banding\">TRUE</property>"
								"<property name=\"enable_grid_lines\">both</property>"
								"<child>"
									"<object class=\"GtkTreeViewColumn\" id=\"tvc_url\">"
										"<property name=\"fixed_width\">400</property>"
										"<property name=\"title\">URL</property>"
										"<property name=\"resizable\">TRUE</property>"
										"<property name=\"sizing\">GTK_TREE_VIEW_COLUMN_FIXED</property>"
										"<child>"
											"<object class=\"GtkCellRendererText\" id=\"rend1\"/>"
											"<attributes>"
												"<attribute name=\"text\">0</attribute>"
											"</attributes>"
										"</child>"
									"</object>"
								"</child>"
								"<child>"
									"<object class=\"GtkTreeViewColumn\" id=\"tvc_ua\">"
										"<property name=\"fixed_width\">200</property>"
										"<property name=\"title\">User Agent</property>"
										"<property name=\"resizable\">TRUE</property>"
										"<property name=\"sizing\">GTK_TREE_VIEW_COLUMN_FIXED</property>"
										"<child>"
											"<object class=\"GtkCellRendererText\" id=\"rend2\"/>"
											"<attributes>"
												"<attribute name=\"text\">1</attribute>"
											"</attributes>"
										"</child>"
									"</object>"
								"</child>"
							"</object>"
						"</child>"
					"</object>"
				"</child>"
			"</object>"
		"</child>"
	"</object>"
"</interface>";


#define ACT_COPY "copy"
#define ACT_COPYUA "copyua"
#define ACT_SELALL "selall"
#define ACT_WATCH "watch"

static const gchar kPopup_Menu_Ui[] =
"<ui>"
	"<popup>"
		"<menuitem action=\""ACT_COPY"\"/>"
		"<menuitem action=\""ACT_COPYUA"\"/>"
		"<menuitem action=\""ACT_SELALL"\"/>"
		"<menuitem action=\""ACT_WATCH"\"/>"
	"</popup>"
"</ui>";

void CopySelURL( GtkTreeView* treeview )
{
	GtkTreeModel *model;
	GList *list, *i;
	GtkTreeIter iter;
	string str;
	GValue val = {0};

	list = gtk_tree_selection_get_selected_rows( gtk_tree_view_get_selection( treeview ), &model );
	
	str.clear();
	for( i = g_list_first( list ); i != NULL; i = g_list_next( i ) )
		{
		if( gtk_tree_model_get_iter( model, &iter, (GtkTreePath*)i->data ) )
			{
			gtk_tree_model_get_value( model, &iter, 0, &val );
			str.append( g_value_get_string( &val ) );
			g_value_unset( &val );
			str.push_back( '\n' );
			}//end if
		}//end for

	gtk_clipboard_set_text( gtk_clipboard_get( GDK_SELECTION_CLIPBOARD ), str.c_str(), -1 );

	g_list_foreach( list, (GFunc)gtk_tree_path_free, NULL );
	g_list_free( list );
}//end CopySelURL


void LaunchSelVlc( GtkTreeView* treeview )
{
	GtkTreeModel *model;
	GList *list, *i;
	GtkTreeIter iter;
	string str;
	GValue val = {0};

	list = gtk_tree_selection_get_selected_rows( gtk_tree_view_get_selection( treeview ), &model );
	
	str.clear();
	for( i = g_list_first( list ); i != NULL; i = g_list_next( i ) )
		{
		if( gtk_tree_model_get_iter( model, &iter, (GtkTreePath*)i->data ) )
			{
			gtk_tree_model_get_value( model, &iter, 0, &val );
			str.append( g_value_get_string( &val ) );
			g_value_unset( &val );
			str.push_back( '\n' );
			}//end if
		}//end for

		char buffer[1000]="su man -c vlc\\ ";

	system(strcat(buffer, str.c_str()));

	g_list_foreach( list, (GFunc)gtk_tree_path_free, NULL );
	g_list_free( list );
}//end LaunchSelVlc

void OnWatch( GtkAction* action, GtkBuilder* builder )
{
	LaunchSelVlc( GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_SNIFF )) );
}//end OnWatch


void OnCopy( GtkAction* action, GtkBuilder* builder )
{
	CopySelURL( GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_SNIFF )) );
}//end OnCopy

void OnCopyUA( GtkAction* action, GtkBuilder* builder )
{
	GtkTreeModel *model;
	GList *list, *i;
	GtkTreeIter iter;
	GValue val = {0};

	list = gtk_tree_selection_get_selected_rows( gtk_tree_view_get_selection( GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_SNIFF )) ), &model );
	
	if( (i = g_list_first( list )) != NULL )
		{
		if( gtk_tree_model_get_iter( model, &iter, (GtkTreePath*)i->data ) )
			{
			gtk_tree_model_get_value( model, &iter, 1, &val );

			gtk_clipboard_set_text( gtk_clipboard_get( GDK_SELECTION_CLIPBOARD ), g_value_get_string( &val ), -1 );

			g_value_unset( &val );
			}//end if
		}//end if

	g_list_foreach( list, (GFunc)gtk_tree_path_free, NULL );
	g_list_free( list );
}//end OnCopyUA

void OnSelAll( GtkAction* action, GtkBuilder* builder )
{
	gtk_tree_selection_select_all( gtk_tree_view_get_selection( GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_SNIFF )) ) );
}//end OnSelAll

static const GtkActionEntry kMenuitem_Action[] =
{
	{ ACT_COPY, NULL, "_Copy Selected URL(s)\tCtrl+C", NULL, NULL, G_CALLBACK(OnCopy) },
	{ ACT_COPYUA, NULL, "Copy _User Agent", NULL, NULL, G_CALLBACK(OnCopyUA) },
	{ ACT_SELALL, NULL, "_Select All\t\tCtrl+A", NULL, NULL, G_CALLBACK(OnSelAll) },
	{ ACT_WATCH, NULL, "_Watch this URL with vlc", NULL, NULL, G_CALLBACK(OnWatch) }
};

static const gchar *kFilterURLSample[] =
{
	".c.youtube.com",
	"av.vimeo.com",
	".flv",
	".mp4",
	NULL
};

static const gchar *kFilterUASample[] =
{
	"Firefox",
	"Chrome",
	"Safari",
	"MSIE",
	"iTunes",
	NULL
};

void term_handler( int sig )
{
	delete ms;
	ms = NULL;
	signal( sig, SIG_DFL );
	raise( sig );
}//end term_handler

void ShowRecord( GtkListStore *lstore, const SniffRec* rec )
{
	gdk_threads_enter();
	if( (url_filter[0] == '\0' || strcasestr( rec->url.c_str(), url_filter ) != NULL)
		&& (ua_filter[0] == '\0' || strcasestr( rec->ua.c_str(), ua_filter ) != NULL) )
		{
		gtk_list_store_insert_with_values( lstore, NULL, -1,
			0, rec->url.c_str(),
			1, rec->ua.c_str(),
			-1 );
		}//end if
	gdk_threads_leave();
}//end ShowRecord

void EnableWndAndMenu( GtkBuilder* builder, gboolean start_sniff )
{
	gtk_widget_set_sensitive( GTK_WIDGET(gtk_builder_get_object( builder, ID_BUTT_START )), !start_sniff );
	gtk_widget_set_sensitive( GTK_WIDGET(gtk_builder_get_object( builder, ID_BUTT_STOP )), start_sniff );
	gtk_widget_set_sensitive( GTK_WIDGET(gtk_builder_get_object( builder, ID_MENU_START )), !start_sniff );
	gtk_widget_set_sensitive( GTK_WIDGET(gtk_builder_get_object( builder, ID_MENU_STOP )), start_sniff );
	gtk_window_set_title( GTK_WINDOW(gtk_builder_get_object( builder, ID_WINDOW_MAIN )),
		start_sniff ? "Media Sniffer - Sniffing" : DLG_TITLE );
}//end EnableWndAndMenu

void SetupComboBoxEntry( GtkComboBoxEntry *combo, const gchar *text[] )
{
	int i;

    gtk_combo_box_set_model( GTK_COMBO_BOX(combo), GTK_TREE_MODEL(gtk_list_store_new( 1, G_TYPE_STRING )) );
    gtk_combo_box_entry_set_text_column( combo, 0 );
	for( i = 0; text[i] != NULL; ++i )
		{
		gtk_combo_box_append_text( GTK_COMBO_BOX(combo), text[i] );
		}//end for
}//end SetupComboBoxEntry

void OnStart( GtkWidget *widget, GtkBuilder *builder )
{
	gtk_list_store_clear( GTK_LIST_STORE(gtk_builder_get_object( builder, ID_LISTST_SNIFF )) );
	if( ms->StartSniff( cfg.adapter, cfg.dst_port, cfg.filter ? cfg.filterwords : NULL, cfg.filteridurl ) )
		{
		EnableWndAndMenu( builder, TRUE );
		}
	else{
		GtkWidget* dlg = gtk_message_dialog_new( GTK_WINDOW(gtk_builder_get_object( builder, ID_WINDOW_MAIN )),
							GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Failed to start sniff! Please check preferences." );
		gtk_window_set_title( GTK_WINDOW(dlg), DLG_TITLE );
		gtk_dialog_run( GTK_DIALOG( dlg ) );
		gtk_widget_destroy( dlg );
		}//end if
}//end OnStart

void OnStop( GtkWidget *widget, GtkBuilder *builder )
{
	ms->StopSniff();
	EnableWndAndMenu( builder, FALSE );
	if( ms->get_record_num() == 0 && cfg.filter )
		{
		GtkWidget* dlg = gtk_message_dialog_new( GTK_WINDOW(gtk_builder_get_object( builder, ID_WINDOW_MAIN )),
							GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE,
			"Nothing sniffed!\n\nYou may try to uncheck the \"Capture URLs with the following extensions\" option and sniff again." );
		gtk_window_set_title( GTK_WINDOW(dlg), DLG_TITLE );
		gtk_dialog_run( GTK_DIALOG( dlg ) );
		gtk_widget_destroy( dlg );
		}//end if
}//end OnStop

void OnPref( GtkMenuItem *menuitem, gpointer )
{
	if( EditConfigDlg( &cfg ) )
		{
		SaveConfig( cfgfile, &cfg );
		}//end if
}//end OnPref

void OnUpdate( GtkMenuItem *menuitem, gpointer )
{
	CheckForUpdates( false );
}//end OnUpdate

void OnAbout( GtkMenuItem *menuitem, gpointer )
{
	const gchar *author[] = { "Qiyi Caitian <qiyi.caitian@gmail.com>", NULL };
	static GtkWidget* dlg = NULL;
	gchar *path;
	GdkPixbuf *pixbuf;

	if( dlg == NULL )
		{
		dlg = gtk_about_dialog_new();
		gtk_about_dialog_set_program_name( GTK_ABOUT_DIALOG( dlg ), DLG_TITLE );
		gtk_about_dialog_set_version( GTK_ABOUT_DIALOG( dlg ), kVersion );
		gtk_about_dialog_set_copyright( GTK_ABOUT_DIALOG( dlg ), "Copyright © 2010-2013 Qiyi Caitian" );
		gtk_about_dialog_set_comments( GTK_ABOUT_DIALOG( dlg ),
				"Sniff download links of online media." );
		gtk_about_dialog_set_website( GTK_ABOUT_DIALOG( dlg ), kHomePage );
		gtk_about_dialog_set_authors( GTK_ABOUT_DIALOG( dlg ), author );

		path = gnome_program_locate_file( NULL, GNOME_FILE_DOMAIN_APP_PIXMAP,
				kIconFile, TRUE, NULL );
		if( path != NULL )
			{
			pixbuf = gdk_pixbuf_new_from_file_at_size( path, 48, 48, NULL );
			gtk_window_set_icon_from_file( GTK_WINDOW(dlg), path, NULL );
			g_free( path );
			gtk_about_dialog_set_logo( GTK_ABOUT_DIALOG(dlg), pixbuf );
			g_object_unref( pixbuf );
			}//end if

		gtk_dialog_run( GTK_DIALOG( dlg ) );
		gtk_widget_destroy( dlg );
		dlg = NULL;
		}//end if
}//end OnAbout

void OnApply( GtkButton *button, GtkBuilder *builder )
{
	GtkListStore *lstore;
	int i, num;

	strncpy( url_filter, gtk_entry_get_text( GTK_ENTRY(gtk_bin_get_child( GTK_BIN(gtk_builder_get_object( builder, ID_COMBO_URLF )) )) ),
		sizeof(url_filter) );
	url_filter[sizeof(url_filter)-1] = '\0';
	strncpy( ua_filter, gtk_entry_get_text( GTK_ENTRY(gtk_bin_get_child( GTK_BIN(gtk_builder_get_object( builder, ID_COMBO_UAF )) )) ),
		sizeof(ua_filter) );
	ua_filter[sizeof(ua_filter)-1] = '\0';

	lstore = GTK_LIST_STORE(gtk_builder_get_object( builder, ID_LISTST_SNIFF ));
	gtk_list_store_clear( lstore );
	num = ms->get_record_num();
	for( i = 0; i < num; ++i )
		{
		if( (url_filter[0] == '\0' || strcasestr( (*ms)[i].url.c_str(), url_filter ) != NULL)
				&& (ua_filter[0] == '\0' || strcasestr( (*ms)[i].ua.c_str(), ua_filter ) != NULL) )
			{
			gtk_list_store_insert_with_values( lstore, NULL, -1,
				0, (*ms)[i].url.c_str(),
				1, (*ms)[i].ua.c_str(),
				-1 );
			}//end if
		}//end for
}//end OnApply

gboolean OnTreeEvent( GtkTreeView *treeview, GdkEvent *event, GtkUIManager* ui_manager )
{
	switch( event->type )
		{
		case GDK_BUTTON_PRESS:
			{
			if( ((GdkEventButton*)event)->button == 3 ) // right button
				{
				gtk_menu_popup( GTK_MENU(gtk_ui_manager_get_widget( ui_manager, "ui/popup" )), NULL, NULL, NULL, NULL,
					((GdkEventButton*)event)->button, ((GdkEventButton*)event)->time );
				return TRUE;
				}//end if
			}break;//end GDK_BUTTON_PRESS

		case GDK_KEY_PRESS:
			{
			if( (((GdkEventKey*)event)->keyval == GDK_KEY_C || ((GdkEventKey*)event)->keyval == GDK_KEY_c)
				&& (((GdkEventKey*)event)->state & (GDK_SHIFT_MASK|GDK_LOCK_MASK|GDK_CONTROL_MASK)) == GDK_CONTROL_MASK ) // Ctrl+C
				{
				CopySelURL( treeview );
				return TRUE;
				}//end if
			}break;//end GDK_KEY_PRESS

		default:break;
		}//end switch
	
	return FALSE;
}//end OnTreeEvent

gboolean PopupMenu( GtkTreeView* treeview, GtkUIManager* ui_manager )
{
	gtk_menu_popup( GTK_MENU(gtk_ui_manager_get_widget( ui_manager, "ui/popup" )), NULL, NULL, NULL, NULL, 0, gtk_get_current_event_time() );
	return TRUE;
}//end PopupMenu

void MainDlg(void)
{
	GtkUIManager *ui_manager;
	GtkActionGroup *act_group;
	GtkBuilder *builder;
	GtkWidget *win;
	GtkTreeView *treeview;
	GtkComboBoxEntry *combo_box;
	GtkMenu *menu;
	gchar *path;

	builder = gtk_builder_new();
	gtk_builder_add_from_string( builder, kMainDlg_Ui, -1, NULL );

	combo_box = GTK_COMBO_BOX_ENTRY(gtk_builder_get_object( builder, ID_COMBO_URLF ));
	SetupComboBoxEntry( combo_box, kFilterURLSample );

	combo_box = GTK_COMBO_BOX_ENTRY(gtk_builder_get_object( builder, ID_COMBO_UAF ));
	SetupComboBoxEntry( combo_box, kFilterUASample );

	g_signal_connect( gtk_builder_get_object( builder, ID_BUTT_START ), "clicked", G_CALLBACK(OnStart), builder );
	g_signal_connect( gtk_builder_get_object( builder, ID_MENU_START ), "activate", G_CALLBACK(OnStart), builder );

	g_signal_connect( gtk_builder_get_object( builder, ID_BUTT_STOP ), "clicked", G_CALLBACK(OnStop), builder );
	g_signal_connect( gtk_builder_get_object( builder, ID_MENU_STOP ), "activate", G_CALLBACK(OnStop), builder );

	g_signal_connect( gtk_builder_get_object( builder, ID_MENU_PREF ), "activate", G_CALLBACK(OnPref), NULL );

	g_signal_connect( gtk_builder_get_object( builder, ID_MENU_UPDATE ), "activate", G_CALLBACK(OnUpdate), NULL );

	g_signal_connect( gtk_builder_get_object( builder, ID_MENU_ABOUT ), "activate", G_CALLBACK(OnAbout), NULL );

	g_signal_connect( gtk_builder_get_object( builder, ID_BUTT_APPLY ), "clicked", G_CALLBACK(OnApply), builder );

	gtk_tree_selection_set_mode( gtk_tree_view_get_selection( GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_SNIFF )) ),
			GTK_SELECTION_MULTIPLE );

	// popup menu
	ui_manager = gtk_ui_manager_new();

	act_group = gtk_action_group_new("PopupMenuAction");
	gtk_action_group_add_actions( act_group, kMenuitem_Action, G_N_ELEMENTS(kMenuitem_Action), builder );
	gtk_ui_manager_insert_action_group( ui_manager, act_group, 0 );
	g_object_unref( act_group );

	gtk_ui_manager_add_ui_from_string( ui_manager, kPopup_Menu_Ui, -1, NULL );
	menu = GTK_MENU(gtk_ui_manager_get_widget( ui_manager, "ui/popup" ));
	gtk_widget_show_all( GTK_WIDGET(menu) );
	gtk_menu_attach_to_widget( menu, GTK_WIDGET(gtk_builder_get_object( builder, ID_TREE_SNIFF )), NULL);

	treeview = GTK_TREE_VIEW(gtk_builder_get_object( builder, ID_TREE_SNIFF ));
	g_signal_connect( treeview, "event", G_CALLBACK(OnTreeEvent), ui_manager );
	g_signal_connect( treeview, "popup-menu", G_CALLBACK(PopupMenu), ui_manager );

	// show window
	win = GTK_WIDGET(gtk_builder_get_object( builder, ID_WINDOW_MAIN ));
	g_signal_connect( win, "delete-event", G_CALLBACK(gtk_main_quit), NULL );
	path = gnome_program_locate_file( NULL, GNOME_FILE_DOMAIN_APP_PIXMAP, kIconFile, TRUE, NULL );
	if( path != NULL )
		{
		gtk_window_set_icon_from_file( GTK_WINDOW(win), path, NULL );
		g_free( path );
		}//end if

	EnableWndAndMenu( builder, FALSE );

	url_filter[0] = ua_filter[0] = '\0';
	ms->set_show_rec( reinterpret_cast<ShowRec>(ShowRecord), gtk_builder_get_object( builder, ID_LISTST_SNIFF ) );

	gtk_widget_show_all( win );
	OnStart(win,builder);
	gtk_main();

	g_object_unref( ui_manager );
	g_object_unref( builder );
}//end MainDlg

int main( int argc, char* argv[] )
{
	bool succ;

	GetConfigFilePath( kConfigFile, cfgfile );

	signal( SIGINT, term_handler );
	signal( SIGQUIT, term_handler );
	signal( SIGABRT, term_handler );
	signal( SIGTERM, term_handler );

	gdk_threads_init();
	gdk_threads_enter();
	gtk_init( &argc, &argv );

	if( getuid() != 0 )
		{
		GtkWidget* dlg = gtk_message_dialog_new( NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, kRunAsRoot );
		gtk_window_set_title( GTK_WINDOW(dlg), DLG_TITLE );
		gtk_dialog_run( GTK_DIALOG( dlg ) );
		gtk_widget_destroy( dlg );
		}
	else{
		gnome_program_init( DLG_TITLE, kVersion, LIBGNOMEUI_MODULE, argc, argv,
				GNOME_PROGRAM_STANDARD_PROPERTIES, GNOME_PARAM_APP_DATADIR,
				DATADIR, NULL );

		// prevent the user to click the uri and open the browser as root
		gtk_about_dialog_set_url_hook( NULL, NULL, NULL );
		gtk_about_dialog_set_email_hook( NULL, NULL, NULL );

		succ = LoadConfig( cfgfile, &cfg );
		if( !succ )
			{
			if( EditConfigDlg( &cfg ) )
				{
				SaveConfig( cfgfile, &cfg );
				succ = true;
				}//end if
			}//end if
		if( succ )
			{
			if( cfg.checkupdate )
				{
				CheckForUpdates( true );
				}//end if
			ms = new MediaSniffer;

			MainDlg();

			delete ms;
			ms = NULL;
			}//end if
		}//end if

	gdk_threads_leave();

	return 0;
}//end main
