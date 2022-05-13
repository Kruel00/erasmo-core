#include <gtk/gtk.h>

int main(){
    GtkWidget *window;
    GtkWidget *grid;
    GtkWidget *status_bar;
    guint context_id;


    gtk_init(NULL,NULL);


    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(window),1024,720);

    grid = gtk_grid_new();
    gtk_grid_set_row_homogeneous(GTK_GRID(grid),TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid),TRUE);
    gtk_container_add(GTK_CONTAINER(window),grid);


    status_bar = gtk_statusbar_new();
    context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(status_bar),"Link");
    context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(status_bar),"Link2");
    gtk_container_add(GTK_CONTAINER(grid),status_bar);

    gtk_statusbar_push(GTK_STATUSBAR(status_bar),context_id,"Wait...");
    gtk_statusbar_push(GTK_STATUSBAR(status_bar),context_id,"Wait2...");

    gtk_widget_show_all(window);
    gtk_main();


}