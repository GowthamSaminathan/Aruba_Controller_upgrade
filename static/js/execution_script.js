function user_yes_no(ans){

eid = $("#user_input_eid").text()
ename = $("#user_input_name").text()
jdata = {"input":ans,"e_id":eid,"name":ename}
console.log(jdata);
$.ajax({
    type: 'POST',data:JSON.stringify(jdata),url: '/portal/yes_or_no',contentType: "application/json",dataType: 'json',    
    success:function(results){
      res_results = results["results"];



      if (res_results == "success"){

        $("#user_input_eid").text()
        $("#user_input_name").text()
        $(".user_yes_no").attr("id","tmp");
        $("#user_input").modal('hide');


      }

    } ,error: function(xhr, ajaxOptions, thrownError){

      console.log("** Server resonce - Yes no error");


    }});

}

function pause_stop_upgrade(ans){

if(ans == "P_or_RUNNING"){

ans = $("#P_or_RUNNING").text();
if ( ans == "Pause" ){ans="PAUSE";}
if ( ans == "Resume" ){ans="RUNNING";}

}
job_name = $("#job_name_id").text();
jdata = {"job_name":job_name,"status":status}

$.ajax({
    type: 'POST',data:JSON.stringify(jdata),url: '/portal/job_manage',contentType: "application/json",dataType: 'json',    
    success:function(results){
      res_results = results["results"];



      if (res_results == "success"){

        if (results["message"] == "PAUSE"){$("#P_or_RUNNING").text("Resume");}
        if (results["message"] == "RUNNING"){$("#P_or_RUNNING").text("PAUSE");}


      }

    } ,error: function(xhr, ajaxOptions, thrownError){

      console.log("** Server resonce - pause_stop_upgrade");


    }});

}



// Adding action on creating new row in exection_table
function new_row_action( json ) 
{

try{
  console.log("jobs status update....")
  $("#message_1").text("");
  $("#message_2").text("");
  $("#message_3").text("");
  $("#message_4").text("");
  $("#message_5").text("");
  $("#message_4").attr('class', '');
  
  //console.log(json);
 
   // for ( var i=0, ien=json.length ; i<ien ; i++ ) 
    //{
    //    json[i][0] = '<a href="/message/'+json[i][0]+'>View message</a>';
      
    //}
  only_data = json["data"]



  if (jQuery.isEmptyObject(only_data) == false){
      
      job_name = json["job_name"];
      job_file = json["job_file"];
      job_status = json["job_status"];
      job_start_date = json["job_start_date"];
      job_end_date = json["job_end_date"];
      job_msg = json["job_msg"];


      if (job_status == "RUNNING") { $("#message_4").attr('class', 'spinner-border text-primary');}
      if (job_status == "COMPLETED") {$("#running_status_live").hide();}else{$("#running_status_live").show();}

      if (job_status == "PAUSE" || job_status == "PAUSED"){$("#P_or_RUNNING").text("Resume")}else{$("#P_or_RUNNING").text("Pause")}

      message_1 = "JOB "+job_status +": "+job_file
      if(job_msg == "None" || job_msg == ""){message_2 = "";}else{message_2 = job_msg;}
      
      console.log(job_end_date);
      message_3 = "Started: "+job_start_date
      if(job_end_date == "" || job_end_date == "None"){}else{message_3 = message_3+ " Completed: "+job_end_date;}
      

      //$("#load-status").attr('class', 'badge badge-danger');
      $("#job_name_id").text(job_name);
      $("#message_1").text(message_1);
      $("#message_2").text(message_2);
      $("#message_3").text(message_3);

      jQuery.each(only_data, function(i, val){
      status = val[5];
      style_val = 'style="text-align:left;white-space=nowrap"'
      if (status.indexOf("RUNNING") == 0)
      {

        val[5] = '<span class="badge badge-warning"'+style_val+'>'+val[5]+'</span>'
        t = status + " " + val[6] + " - Host:"+val[2];
        $("#message_5").text(t);
       
         

      }else if (status.indexOf("PENDING") == 0){

         val[5] = '<span class="badge badge-info"'+style_val+'>'+val[5]+'</span>'
        


      }else if (status.indexOf("COMPLETED") == 0){

         val[5] = '<span class="badge badge-success"'+style_val+'>'+val[5]+'</span>'
         

        
      }else {

        val[5] = '<span class="badge badge-danger"'+style_val+'>'+val[5]+'</span>'

      }

      });
      return only_data;

  }
else{
  $("#job_name_id").text();
  $("#message_1").text("");
  $("#message_2").text("");
  $("#message_3").text("");
  $("#message_4").text("");
  $("#message_4").attr('class', '');
  $("#message_5").text("");
  console.log("Job data not available......");
  console.log(json);
  return [];
}

}catch(e){
console.log("Receiving Job data error");
$("#job_name_id").text();
$("#message_5").text("");
$("#message_4").text("");
$("#message_4").attr('class', '');
$("#message_1").text("");
$("#message_2").text("");
$("#message_3").text("");
return []; 
}
}


/* $(document).ready(function() {
    $('#execution_table').DataTable( {
        "responsive": true,
        "select": true,
        "data": dataSet,
        "columns": [
            { title: "SNo"},
            { title: "Type" },
            { title: "Host" },
            { title: "Version" },
            { title: "Status" },
            { title: "Action" }
        ],
        "columnDefs": [{ "width": "1%", "targets": 0 }
        ],
        "scrollY":        "300px",
        "scrollCollapse": true,
        "paging":         false,
        "createdRow" : new_row_action

} );
});*/


$(document).ready(function() {
    execution_table = $('#execution_table').DataTable( {
        columns: [
            { title: "ID"},
            { title: "Type" },
            { title: "Host Name" },
            { title: "Host" },
            { title: "Version" },
            { title: "Status" },
            { title: "Note" }

        ],
        //"buttons": [ 'copy', 'excel', 'pdf', 'colvis' ],
        lengthChange: false,
        //dom: 'Bfrtip',
        "columnDefs": [{ "visible": false, "targets": [] }],
        "scrollY":        "400px",
        "scrollCollapse": true,
        "paging":         false,
        //"order": [[ 0, "desc" ]],
        "ajax": {
        "url": "/portal/read_last_job",
        "type": "GET",
        "dataSrc": new_row_action,
        },
        buttons: ['copy','pdf','excel',{text: 'My button',action: function ( e, dt, node, config ) {alert( 'Button activated' );}}]
      
      });



} );


function modify_execution_table_data( json ) 
{

try{
  console.log("Reding Events response...")
  //console.log(json);
 
   // for ( var i=0, ien=json.length ; i<ien ; i++ ) 
    //{
    //    json[i][0] = '<a href="/message/'+json[i][0]+'>View message</a>';
      
    //}
  only_data = json["data"]
  if (jQuery.isEmptyObject(only_data) == false){
      jQuery.each(only_data, function(i, val){
      evnt_msg = val[3];
      val[2] = val[2].split(" ")[1];
      style_val = 'style="text-align:left;white-space=nowrap"'
      if (evnt_msg.indexOf("ERROR:") == 0)
      {

        val[2] = '<span class="badge badge-danger"'+style_val+'>'+val[2]+'</span>'
         val[3] = '<span class="badge badge-danger"'+style_val+'>'+val[3]+'</span>'

      }else if (evnt_msg.indexOf("INFO:") == 0){

         val[2] = '<span class="badge badge-info"'+style_val+'>'+val[2]+'</span>'
         val[3] = '<span class="badge badge-info"'+style_val+'>'+val[3]+'</span>'


      }else if (evnt_msg.indexOf("WARNING:") == 0){

         val[2] = '<span class="badge badge-warning"'+style_val+'>'+val[2]+'</span>'
         val[3] = '<span class="badge badge-warning"'+style_val+'>'+val[3]+'</span>'

        
      }else if (evnt_msg.indexOf("IN:") == 0){

         msg = val[3];
         val[2] = '<span class="badge badge-primary"'+style_val+'>'+val[2]+'</span>'
         val[3] = '<span class="badge badge-primary"'+style_val+'>'+val[3]+'</span>'
        
         if(only_data.length == i+1)
         {

          
          msg = msg.split("IN:")[1];
          $("#user_input_msg").text(msg);
          console.log("User Input required : "+msg);
          $("#user_input_eid").text(val[4]);
          $("#user_input_name").text(val[1]);
          $("#user_input").modal({backdrop: "static"});

         }

        
      }
      else{

        val[2] = '<span class="badge badge-warning"'+style_val+'>'+val[2]+'</span>'
         val[3] = '<span class="badge badge-warning"'+style_val+'>'+val[3]+'</span>'

      }

      });
      return only_data;

  }
else{
  console.log("Events data not found")
  console.log(json);
  return [];
}

}catch(e){console.log("Receiving Events error");return [];}}

$(document).ready(function() {
    events_table = $('#execution_events_table').DataTable( {
        columns: [
            { title: "ID" },
            { title: "NAME" },
            { title: "TIME" },
            { title: "EVENTS" },
            { title: "EID" }

        ],
         dom: 'Bfrtip',
        buttons: ['copy', 'excel'],
        "columnDefs": [{ "visible": false, "targets": [0,1,4] }],
        "scrollY":        "400px",
        "order": [[ 0, "desc" ]],
        "scrollCollapse": true,
        "paging":         false,
        //"order": [[ 0, "desc" ]],
        "ajax": {
        "url": "/portal/read_last_events",
        "type": "GET",
        "dataSrc": modify_execution_table_data,
        }
      
      });

} );