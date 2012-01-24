/**
 * Dnieprov es una librería que implementa un driver en JAVA para el DNI 
 * electrónico y un proveedor cryptográfico compatible con la JCA de Java.
 * Código fuente disponible en http://github.com/lfern/dnieprov
 * 
 * Copyright 2012 Luis Fernando Pardo Fincias
 * 
 * Este fichero se distribuye bajo una licencia dúal: LGPL 3.0 y EUPL 1.1:  
 * - GNU Lesser General Public License (LGPL), version 3.0
 * - European Union Public Licence (EUPL), version 1.1
 * ----------------------------------------------------------------------
 * Si se decide por la licencia LGPL, se aplica el siguiente aviso:
 * 
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License
 *   as published by the Free Software Foundation, either version 3
 *   of the License, or (at your option) any later version.   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.  
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see http://www.gnu.org/licenses/
 * 
 * ----------------------------------------------------------------------* 
 * Si se decide por la licencia EUPL se aplica este otro:
 * 
 *   Licencia con arreglo a la EUPL, Versión 1.1 exclusivamente (la "Licencia");
 *   Solo podrá usarse esta obra su se respeta la Licencia.
 *   Puede obtenerse una copia de la Licencia en:
 *   http://ec.europa.eu/idabc/eupl 
 *   El programa distribuido con arreglo a la Licencia se distribuye "TAL CUAL",
 *   SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * ----------------------------------------------------------------------* 
 */
package org.dnieprov.driver;

import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;
import org.dnieprov.driver.exceptions.DnieUnexpectedException;

/**
 *
 * @author luis
 */
    
final class PasswordGuiCallback implements PasswordCallback{
    
    
    @Override
    public char[] getPassword(String title,String msg) throws DnieUnexpectedException{
        final JPasswordField jpf = new JPasswordField();
        JOptionPane jop = new JOptionPane(new Object[]{new JLabel("<HTML>"+msg+"<HTML>"), jpf},
            JOptionPane.QUESTION_MESSAGE,
            JOptionPane.OK_CANCEL_OPTION);
        JDialog dialog = jop.createDialog(title);
        dialog.setAlwaysOnTop(true);
        dialog.addComponentListener(new ComponentAdapter(){
          @Override
          public void componentShown(ComponentEvent e){
            SwingUtilities.invokeLater(new Runnable(){
              @Override
              public void run(){
                jpf.requestFocusInWindow();
              }
            });
          }
        });
        dialog.setVisible(true);
        if (jop.getValue() == null){
            return null;
        }
        int result = (Integer)jop.getValue();
        dialog.dispose();
        if(result == JOptionPane.OK_OPTION){
          return jpf.getPassword();
        }        
        return null;
    }

    @Override
    public void showMessage(String title,String msg) throws DnieUnexpectedException {
        JOptionPane jop = new JOptionPane(new Object[]{new JLabel("<HTML>"+msg+"<HTML>")},
            JOptionPane.WARNING_MESSAGE,
            JOptionPane.DEFAULT_OPTION);
        JDialog dialog = jop.createDialog(title);
        dialog.setAlwaysOnTop(true);
        dialog.setVisible(true);        
    }
    
}
